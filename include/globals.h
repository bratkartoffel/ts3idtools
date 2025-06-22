#ifndef TS3IDTOOLS_GLOBALS_H
#define TS3IDTOOLS_GLOBALS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/bn.h>

#ifndef SHA_DIGEST_LENGTH
#  define SHA_DIGEST_LENGTH 20
#endif

#define PRIVKEY_LEN_OBFUSCATED_B64 192
#define PUBKEY_LEN_OBFUSCATED_B64  128
#define PUBKEY_LEN_B64             128
#define OBFUSCATION_KEY_LEN        128
#define OBFUSCATION_KEY            ((const uint8_t *) "b9dfaa7bee6ac57ac7b65f1094a1c155e747327bc2fe5d51c512023fe54a280201004e90ad1daaae1075d53b7d571c30e063b5a62a4a017bb394833aa0983e6e")
#define MAX_MSG_LENGTH_2_BLOCKS    119

#define debug_printf(fmt, ...)                    \
    do {                                          \
        if (debug) {                              \
            fprintf(stderr, fmt, ##__VA_ARGS__);  \
            fflush(stderr);                       \
        }                                         \
    } while (0)

#define debug_print_hex(prefix, x, len)                      \
    do {                                                     \
        if(debug) {                                          \
            debug_printf("%s=", prefix);                     \
            for (int i = 0; i < (int) len; i++) {            \
                debug_printf("%02x ", ((uint8_t*)(x))[i]);   \
            }                                                \
            debug_printf("\n");                              \
        }                                                    \
    } while (0)

typedef unsigned char ts3_privkey_t;
typedef unsigned char ts3_pubkey_t;
typedef unsigned char ts3_uuid_t;

extern bool debug;

uint8_t get_security_level(ts3_pubkey_t* pubkey, uint64_t counter);

uint8_t leading_zero_bits(uint32_t hash[5]);

size_t append_counter(uint8_t data[PUBKEY_LEN_B64], size_t length, uint64_t value);

size_t increment_counter(uint8_t data[PUBKEY_LEN_B64], size_t pubkey_length, size_t complete_length);

bool ts3_xor(size_t a_len, const uint8_t *a, int aoffs,
             size_t b_len, const uint8_t *b, int boffs,
             size_t len,
             size_t outBuf_len, uint8_t *outBuf, int outOffs);

void create_pubkey(const BIGNUM *x, const BIGNUM *y,
                   size_t *pubkey_len, ts3_pubkey_t pubkey[*pubkey_len]);

void create_privkey(const BIGNUM *x, const BIGNUM *y, const BIGNUM *z,
                    size_t *privkey_len, ts3_privkey_t privkey[*privkey_len]);

void create_uuid(size_t pubkey_len, ts3_pubkey_t pubkey[pubkey_len],
                 size_t *uuid_len, ts3_uuid_t uuid[*uuid_len]);

void print_bignum(const char *format, const BIGNUM *num);

#endif //TS3IDTOOLS_GLOBALS_H
