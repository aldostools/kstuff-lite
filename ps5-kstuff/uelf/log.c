#include "log.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "utils.h"

#if KSTUFF_OBS
static inline void log_spin_pause(void)
{
    __asm__ volatile("pause");
}
#endif

void log_word(uint64_t word)
{
#if KSTUFF_OBS
    uint64_t seq = __atomic_fetch_add(&shared_area.word_log.next_seq, 1, __ATOMIC_RELAXED);
    struct kstuff_word_log_entry* entry = &shared_area.word_log.entries[seq % SHARED_LOG_WORD_CAP];
    __atomic_store_n(&entry->seq, 0, __ATOMIC_RELAXED);
    entry->word = word;
    __atomic_store_n(&entry->seq, seq + 1, __ATOMIC_RELEASE);
    METRIC_INC(log_word_writes);
#else
    (void)word;
#endif
}

void log_msg(const char* msg)
{
#if KSTUFF_OBS
    if(!msg)
        return;
    size_t len = strlen(msg);
    if(!len)
        return;
    if(len > SHARED_LOG_MSG_CAP)
    {
        msg += len - SHARED_LOG_MSG_CAP;
        len = SHARED_LOG_MSG_CAP;
    }
    while(__atomic_exchange_n(&shared_area.msg_log.write_lock, 1, __ATOMIC_ACQ_REL))
        log_spin_pause();
    uint64_t seq = shared_area.msg_log.next_seq;
    size_t off = seq % SHARED_LOG_MSG_CAP;
    size_t first = SHARED_LOG_MSG_CAP - off;
    if(first > len)
        first = len;
    memcpy(shared_area.msg_log.bytes + off, msg, first);
    if(len > first)
        memcpy(shared_area.msg_log.bytes, msg + first, len - first);
    __atomic_store_n(&shared_area.msg_log.next_seq, seq + len, __ATOMIC_RELEASE);
    __atomic_store_n(&shared_area.msg_log.write_lock, 0, __ATOMIC_RELEASE);
    METRIC_INC(log_msg_writes);
    METRIC_ADD(log_msg_bytes, len);
#else
    (void)msg;
#endif
}

#if KSTUFF_OBS
static int virt2phys_untracked(uint64_t addr, uint64_t* phys, uint64_t* phys_limit)
{
    uint64_t pml = cr3_phys;
    for(int i = 39; i >= 12; i -= 9)
    {
        if(pml >= ((1ull << 39) - (1ull << 12)))
            return 0;
        uint64_t next_pml = *(uint64_t*)(DMEM + pml + ((addr & (0x1ffull << i)) >> (i - 3)));
        if(!(next_pml & 1))
            return 0;
        if((next_pml & 128) || i == 12)
        {
            uint64_t addr1 = next_pml & ((1ull << 52) - (1ull << i));
            addr1 |= addr & ((1ull << i) - 1);
            *phys = addr1;
            *phys_limit = (addr1 | ((1ull << i) - 1)) + 1;
            return 1;
        }
        pml = next_pml & ((1ull << 52) - (1ull << 12));
    }
    return 0;
}

static int copy_to_kernel_untracked(uint64_t dst, const void* src, uint64_t sz)
{
    const char* p_src = src;
    uint64_t phys, phys_end;
    while(sz)
    {
        if(!virt2phys_untracked(dst, &phys, &phys_end))
            return EFAULT;
        size_t chk = phys_end - phys;
        if(sz < chk)
            chk = sz;
        memcpy(DMEM + phys, p_src, chk);
        dst += chk;
        p_src += chk;
        sz -= chk;
    }
    return 0;
}

static void snapshot_metrics(struct kstuff_metrics* out)
{
    const uint64_t* src = (const uint64_t*)&shared_area.metrics;
    uint64_t* dst = (uint64_t*)out;
    for(size_t i = 0; i < sizeof(*out) / sizeof(uint64_t); i++)
        dst[i] = __atomic_load_n(&src[i], __ATOMIC_RELAXED);
}

static void snapshot_word_log_entry(struct kstuff_word_log_entry* out, size_t idx)
{
    for(;;)
    {
        uint64_t seq1 = __atomic_load_n(&shared_area.word_log.entries[idx].seq, __ATOMIC_ACQUIRE);
        if(!seq1)
        {
            out->seq = 0;
            out->word = 0;
            return;
        }
        out->word = shared_area.word_log.entries[idx].word;
        uint64_t seq2 = __atomic_load_n(&shared_area.word_log.entries[idx].seq, __ATOMIC_ACQUIRE);
        if(seq1 == seq2)
        {
            out->seq = seq2;
            return;
        }
    }
}

static void snapshot_word_log(struct kstuff_word_log* out)
{
    out->next_seq = __atomic_load_n(&shared_area.word_log.next_seq, __ATOMIC_ACQUIRE);
    for(size_t i = 0; i < SHARED_LOG_WORD_CAP; i++)
        snapshot_word_log_entry(&out->entries[i], i);
}

static void snapshot_msg_log(struct kstuff_msg_log* out)
{
    for(;;)
    {
        if(__atomic_load_n(&shared_area.msg_log.write_lock, __ATOMIC_ACQUIRE))
        {
            log_spin_pause();
            continue;
        }
        uint64_t seq1 = __atomic_load_n(&shared_area.msg_log.next_seq, __ATOMIC_ACQUIRE);
        memcpy(out->bytes, shared_area.msg_log.bytes, sizeof(out->bytes));
        if(!__atomic_load_n(&shared_area.msg_log.write_lock, __ATOMIC_ACQUIRE))
        {
            out->write_lock = 0;
            out->next_seq = seq1;
            return;
        }
    }
}

int copy_shared_area_snapshot(uint64_t dst, uint64_t sz)
{
    if(sz < sizeof(struct kstuff_snapshot))
        return EINVAL;

    struct
    {
        uint64_t bitmask;
        uint64_t ready_mask;
        struct kstuff_metrics metrics;
    } header;
    struct kstuff_word_log word_log;
    struct kstuff_msg_log msg_log;

    header.bitmask = __atomic_load_n(&shared_area.bitmask, __ATOMIC_ACQUIRE);
    header.ready_mask = __atomic_load_n(&shared_area.ready_mask, __ATOMIC_ACQUIRE);
    snapshot_metrics(&header.metrics);
    snapshot_word_log(&word_log);
    snapshot_msg_log(&msg_log);

    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, bitmask), &header, sizeof(header)))
        return EFAULT;
    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, word_log), &word_log, sizeof(word_log)))
        return EFAULT;
    if(copy_to_kernel_untracked(dst + offsetof(struct kstuff_snapshot, msg_log), &msg_log, sizeof(msg_log)))
        return EFAULT;
    return 0;
}
#else
int copy_shared_area_snapshot(uint64_t dst, uint64_t sz)
{
    (void)dst;
    (void)sz;
    return ENOSYS;
}
#endif
