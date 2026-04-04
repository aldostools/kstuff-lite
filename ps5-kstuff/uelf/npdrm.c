// https://github.com/PS5Dev/Byepervisor/blob/57204cbd7bd26ed4623634d52b0f60f40d630087/hen/src/fpkg.cpp#L82

#include <string.h>
#include "utils.h"
#include "npdrm.h"
#include "log.h"
#include "fpu.h"
#include "sha256.h"

#include <isa-l_crypto/aes_cbc.h>
#include <isa-l_crypto/aes_keyexp.h>

// #define NPDRM_PORTING 1

#ifndef NPDRM_PORTING
extern char sceSblServiceMailbox_lr_npdrm_cmd_5[];
extern char sceSblServiceMailbox_lr_npdrm_cmd_6[];
#endif
extern char sceSblServiceMailbox[];

static const uint8_t rif_debug_key[] = {0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12};

enum { AES128_EXPKEY_SIZE = 16 * 11 };

static struct
{
    uint8_t enc_exp_key[AES128_EXPKEY_SIZE] __attribute__((aligned(16)));
    uint8_t dec_exp_key[AES128_EXPKEY_SIZE] __attribute__((aligned(16)));
    int valid;
} s_rif_debug_key_schedule;

static int aes_cbc_128_decrypt_rif_debug_fpu_held(uint8_t *out, const uint8_t *in, int size, const uint8_t *iv)
{
    int err = -1;
    if (!s_rif_debug_key_schedule.valid)
    {
        if (isal_aes_keyexp_128(rif_debug_key, s_rif_debug_key_schedule.enc_exp_key,
                                s_rif_debug_key_schedule.dec_exp_key))
            goto exit;
        s_rif_debug_key_schedule.valid = 1;
    }
    if (isal_aes_cbc_dec_128(in, iv, s_rif_debug_key_schedule.dec_exp_key, out, size))
        goto exit;
    err = 0;
exit:
    return err;
}

static int sha256_buffer_fpu_held(const unsigned char *in, unsigned long inlen, unsigned char *out)
{
    struct uelf_sha256_context ctx;
    int err = -1;

    uelf_sha256_init(&ctx);
    if(uelf_sha256_update(&ctx, in, inlen))
        goto exit;
    if(uelf_sha256_final(&ctx, out))
        goto exit;
    err = 0;
exit:
    return err;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    for (size_t i = 0; i < n; i++)
    {
        if (p1[i] != p2[i])
        {
            return (int)p1[i] - (int)p2[i];
        }
    }
    return 0;
}

int try_handle_npdrm_mailbox(uint64_t *regs, uint64_t lr)
{
    struct {
        uint32_t cmd;
        uint32_t _pad;
        uint64_t rif_pa;
    } request_hdr;
#ifndef NPDRM_PORTING
    if (lr != (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_5 &&
        lr != (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_6)
    {
        return 0;
    }
    if (copy_from_kernel(&request_hdr, regs[RDX], sizeof(request_hdr)))
    {
        return 1;
    }
#else
    if (copy_from_kernel(&request_hdr, regs[RDX], sizeof(request_hdr)))
    {
        return 0;
    }
    // Other functions may use this same cmd number for different purposes (depending on RDI/handle i believe, however its value changes between fws)
    // for example, sceSblServiceMailbox_lr_decryptSelfBlock also sees cmd 6
    // if we only relied on this, it would work safely because of the later checks, its just wasteful
    if (request_hdr.cmd != 5 && request_hdr.cmd != 6)
    {
        return 0;
    }
#endif
    METRIC_INC(npdrm_mailbox_total);
    if(request_hdr.cmd == 5)
        METRIC_INC(npdrm_cmd5);
    else if(request_hdr.cmd == 6)
        METRIC_INC(npdrm_cmd6);

    uint64_t rif_pa = request_hdr.rif_pa;

    struct RifCmd56MemoryLayout layout;
    memcpy(&layout, DMEM + rif_pa, sizeof(layout));

    if (layout.rif.type != 0x2)
    {
#ifdef NPDRM_PORTING
        return 0;
#else
        return 1;
#endif
    }

    if (uelf_fpu_enter())
    {
#ifdef NPDRM_PORTING
        return 0;
#else
        return 1;
#endif
    }
    uint8_t contentid_hash[32];
    if (sha256_buffer_fpu_held(layout.rif.contentId, sizeof(layout.rif.contentId), contentid_hash))
    {
        uelf_fpu_exit();
#ifdef NPDRM_PORTING
        return 0;
#else
        return 1;
#endif
    }

    if (memcmp(contentid_hash, layout.rif.rifIv, 16) != 0)
    {
        uelf_fpu_exit();
#ifdef NPDRM_PORTING
        return 0;
#else
        // not a debug rif
        return 1;
#endif
    }
    METRIC_INC(npdrm_debug_rif_matches);

#ifdef NPDRM_PORTING
    // Now that we know the input data is a (debug) rif, we know we are at the right place
    log_word(0x10C7100000000001UL + ((uint64_t)request_hdr.cmd << 16));
    log_word(lr);
#endif

    layout.output.version = __builtin_bswap16(layout.rif.version);
    layout.output.unk04 = __builtin_bswap16(layout.rif.unk06);
    layout.output.psnid = __builtin_bswap64(layout.rif.psnid);
    layout.output.startTimestamp = __builtin_bswap64(layout.rif.startTimestamp);
    layout.output.endTimestamp = __builtin_bswap64(layout.rif.endTimestamp);
    layout.output.extraFlags = __builtin_bswap64(layout.rif.extraFlags);
    layout.output.type = __builtin_bswap16(layout.rif.type);
    layout.output.contentType = __builtin_bswap16(layout.rif.contentType);
    layout.output.skuFlag = __builtin_bswap16(layout.rif.skuFlag);
    layout.output.unk34 = __builtin_bswap32(layout.rif.unk60);
    layout.output.unk38 = __builtin_bswap32(layout.rif.unk64);
    layout.output.unk3C = 0;
    layout.output.unk40 = 0;
    layout.output.unk44 = 0;
    memcpy(layout.output.contentId, layout.rif.contentId, 0x30);
    memcpy(layout.output.rifIv, layout.rif.rifIv, 0x10);
    layout.output.unk88 = __builtin_bswap32(layout.rif.unk70);
    layout.output.unk8C = __builtin_bswap32(layout.rif.unk74);
    layout.output.unk90 = __builtin_bswap32(layout.rif.unk78);
    layout.output.unk94 = __builtin_bswap32(layout.rif.unk7C);
    memcpy(layout.output.unk98, layout.rif.unk80, 0x10);
    if (layout.output.skuFlag == 2)
    {
        layout.output.skuFlag = 1;
    }

#ifdef NPDRM_PORTING
    if (request_hdr.cmd == 6)
#else
    if (lr == (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_6)
#endif
        {
            uint8_t decrypted_secret[sizeof(layout.rif.rifSecret)];
            if (aes_cbc_128_decrypt_rif_debug_fpu_held(decrypted_secret, layout.rif.rifSecret,
                                                       sizeof(layout.rif.rifSecret), layout.rif.rifIv))
            {
                uelf_fpu_exit();
                return 1;
            }

        if (memcmp(contentid_hash + 16, decrypted_secret, 16) != 0)
        {
            uelf_fpu_exit();
            // does not use debug rif key/failed to decrypt?
            return 1;
        }

        // copy both unk10 and unk20
        if(copy_to_kernel(regs[RDX] + __builtin_offsetof(struct NpDrmCmd6, unk10), &decrypted_secret[0x70], 0x20))
        {
            uelf_fpu_exit();
            return 1;
        }
    }

    memcpy(DMEM + rif_pa + __builtin_offsetof(struct RifCmd56MemoryLayout, output), &layout.output, sizeof(layout.output));
    METRIC_INC(npdrm_mailbox_emulated);

    uint32_t res = 0;
    if(copy_to_kernel(regs[RDX] + 0x4, &res, sizeof(res)))
    {
        uelf_fpu_exit();
        return 1;
    }

    uelf_fpu_exit();
    regs[RIP] = lr;
    regs[RAX] = 0;
    regs[RSP] += 8;
    return 1;
}

static const uint64_t dbgregs_for_ioctl[6] = {
    (uint64_t)sceSblServiceMailbox, 0, 0, 0,
    0, 0x401};

void handle_ioctl_syscall(uint64_t *regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_ioctl);
}
