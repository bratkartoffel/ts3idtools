#ifndef TS3IDTOOLS_GLOBALS_H
#define TS3IDTOOLS_GLOBALS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "openssl/sha.h"

#define SHA1_MSG_SIZE              2 * SHA_CBLOCK
#define OBFUSCATION_KEY            ((const uint8_t *) "b9dfaa7bee6ac57ac7b65f1094a1c155e747327bc2fe5d51c512023fe54a280201004e90ad1daaae1075d53b7d571c30e063b5a62a4a017bb394833aa0983e6e")
#define OBFUSCATION_KEY_LEN        128
#define MAX_MSG_LENGTH_2_BLOCKS    119

#define debug_printf(fmt, ...)                               \
    do                                                       \
    {                                                        \
        if (debug)                                           \
        {                                                    \
            fprintf(stderr, fmt __VA_OPT__(,) __VA_ARGS__);  \
            fflush(stderr);                                  \
        }                                                    \
    } while (0)

#define debug_print_hex(prefix, x, len)                      \
    do                                                       \
    {                                                        \
        if (debug)                                           \
        {                                                    \
            debug_printf("%s=", prefix);                     \
            for (int i = 0; i < (int) len; i++)              \
            {                                                \
                debug_printf("%02x ", ((uint8_t*)(x))[i]);   \
            }                                                \
            debug_printf("\n");                              \
        }                                                    \
    } while (0)

typedef unsigned char ts3_privkey_t;
typedef unsigned char ts3_pubkey_t;
typedef unsigned char ts3_uuid_t;

extern bool debug;

uint8_t leading_zero_bits(uint32_t hash[5]);

size_t append_counter(uint8_t data[SHA1_MSG_SIZE], size_t length, uint64_t value);

size_t increment_counter(uint8_t data[SHA1_MSG_SIZE], size_t pubkey_length, size_t complete_length);

bool check_for_intel_sha_extensions();

#ifndef HAVE_STRNDUP
char* strndup(const char* str, size_t maxlen);
#endif
#endif //TS3IDTOOLS_GLOBALS_H
