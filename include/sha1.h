#include <stdint.h>

#ifndef TS3IDGEN_SHA1_H
#define TS3IDGEN_SHA1_H

void do_sha1_first_block(uint8_t data[128], uint32_t state[5]);

void do_sha1_second_block_cpu(uint8_t data[128], size_t len, uint32_t state[5], uint8_t hash[20]);

void do_sha1_second_block_software(uint8_t data[128], size_t len, uint32_t state[5], uint8_t hash[20]);

void sha1_compress_cpu(uint32_t digest[5], const uint8_t *block);

void sha1_compress_software(uint32_t state[5], const uint8_t *data);

#endif //TS3IDGEN_SHA1_H
