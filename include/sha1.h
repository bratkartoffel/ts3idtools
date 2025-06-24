#ifndef TS3IDTOOLS_SHA1_H
#define TS3IDTOOLS_SHA1_H

#include <stdint.h>

void do_sha1_first_block(uint8_t data[128], uint32_t state[5]);

void do_sha1_second_block_with_cpu_ext(uint8_t data[128], size_t len, const uint32_t state[5], uint32_t hash[5]);

void do_sha1_second_block_without_cpu_ext(uint8_t data[128], size_t len, const uint32_t state[5], uint32_t hash[5]);

#endif //TS3IDTOOLS_SHA1_H
