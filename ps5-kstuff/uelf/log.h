#pragma once
#include <sys/types.h>
#include "shared_area.h"

void log_word(uint64_t word);
void log_msg(const char* msg);
int copy_shared_area_snapshot(uint64_t dst, uint64_t sz);
