#include "globals.h"
#include "sha1.h"

#include <immintrin.h>

bool initialized = false;

void do_sha1_first_block(uint8_t data[128], uint32_t state[5]) {
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;

    sha1_compress_software(state, data);
#if 0
    // for debugging / verifying optimizations
    debug_printf("===========================\n");
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    debug_printf("===========================\n");
#endif
}

void do_sha1_second_block_without_cpu_ext(uint8_t data[128], size_t len, const uint32_t state[5], uint32_t hash[5]) {
    // prepare second block
    uint8_t *block = data + 64;
    block[len - 64] = 0x80;

    // length is in bits and always < 16 bit
    len *= 8;
    block[62] = len >> 8;
    block[63] = len & 0xFF;

    memcpy(hash, state, SHA_DIGEST_LENGTH);
    sha1_compress_software(hash, block);
#if 0
    // for debugging / verifying optimizations
    debug_printf("===========================\n");
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    debug_printf("===========================\n");
#endif
}

void do_sha1_second_block_with_cpu_ext(uint8_t data[128], size_t len, const uint32_t state[5], uint32_t hash[5]) {
    // prepare second block
    uint8_t *block = data + 64;
    block[len - 64] = 0x80;

    // length is in bits and always < 16 bit
    len *= 8;
    block[62] = len >> 8;
    block[63] = len & 0xFF;

    memcpy(hash, state, SHA_DIGEST_LENGTH);
    sha1_compress_cpu(hash, block);
#if 0
    // for debugging / verifying optimizations
    debug_printf("===========================\n");
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    debug_printf("===========================\n");
#endif
}

void sha1_compress_cpu(uint32_t digest[5], const uint8_t *block) {
    __m128i abcd, e0 = {0}, e1;
    __m128i abcd_save, e_save;
    __m128i msg0, msg1, msg2, msg3;
    __m128i shuf_mask, e_mask;

    e_mask = _mm_set_epi64x(0xFFFFFFFF00000000ull, 0x0000000000000000ull);
    shuf_mask = _mm_set_epi64x(0x0001020304050607ull, 0x08090a0b0c0d0e0full);

    // Load initial hash values
    abcd = _mm_loadu_si128((__m128i *) digest);
    e0 = _mm_insert_epi32(e0, *(digest + 4), 3);
    abcd = _mm_shuffle_epi32(abcd, 0x1B);
    e0 = _mm_and_si128(e0, e_mask);

    // Save hash values for addition after rounds
    abcd_save = abcd;
    e_save = e0;

    // Rounds 0-3
    msg0 = _mm_loadu_si128((__m128i *) block);
    msg0 = _mm_shuffle_epi8(msg0, shuf_mask);
    e0 = _mm_add_epi32(e0, msg0);
    e1 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);

    // Rounds 4-7
    msg1 = _mm_loadu_si128((__m128i *) (block + 16));
    msg1 = _mm_shuffle_epi8(msg1, shuf_mask);
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);

    // Rounds 8-11
    msg2 = _mm_loadu_si128((__m128i *) (block + 32));
    msg2 = _mm_shuffle_epi8(msg2, shuf_mask);
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);

    // Rounds 12-15
    msg3 = _mm_loadu_si128((__m128i *) (block + 48));
    msg3 = _mm_shuffle_epi8(msg3, shuf_mask);
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);

    // Rounds 16-19
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);

    // Rounds 20-23
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg3 = _mm_xor_si128(msg3, msg1);

    // Rounds 24-27
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);

    // Rounds 28-31
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);

    // Rounds 32-35
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);

    // Rounds 36-39
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg3 = _mm_xor_si128(msg3, msg1);

    // Rounds 40-43
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);

    // Rounds 44-47
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);

    // Rounds 48-51
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);

    // Rounds 52-55
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg3 = _mm_xor_si128(msg3, msg1);

    // Rounds 56-59
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);

    // Rounds 60-63
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);

    // Rounds 64-67
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);

    // Rounds 68-71
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
    msg3 = _mm_xor_si128(msg3, msg1);

    // Rounds 72-75
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);

    // Rounds 76-79
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);

    // Add current hash values with previously saved
    e0 = _mm_sha1nexte_epu32(e0, e_save);
    abcd = _mm_add_epi32(abcd, abcd_save);

    abcd = _mm_shuffle_epi32(abcd, 0x1B);
    _mm_store_si128((__m128i *) digest, abcd);
    *(digest + 4) = _mm_extract_epi32(e0, 3);
}

#define ROUNDTAIL(a, b, e, f, i, k)  \
    e += (a << 5 | a >> 27) + f + k + schedule[i & 0xF];  \
    b = b << 30 | b >> 2;

#define SCHEDULE(i)  \
    temp = schedule[(i - 3) & 0xF] ^ schedule[(i - 8) & 0xF] ^ schedule[(i - 14) & 0xF] ^ schedule[(i - 16) & 0xF];  \
    schedule[i & 0xF] = temp << 1 | temp >> 31;

#define ROUND0a(a, b, c, d, e, i)  \
    schedule[i] = (block[i] << 24) | ((block[i] & 0xFF00) << 8) | ((block[i] >> 8) & 0xFF00) | (block[i] >> 24);  \
    ROUNDTAIL(a, b, e, ((b & c) | (~b & d)), i, 0x5A827999)

#define ROUND0b(a, b, c, d, e, i)  \
    SCHEDULE(i)  \
    ROUNDTAIL(a, b, e, ((b & c) | (~b & d)), i, 0x5A827999)

#define ROUND1(a, b, c, d, e, i)  \
    SCHEDULE(i)  \
    ROUNDTAIL(a, b, e, (b ^ c ^ d), i, 0x6ED9EBA1)

#define ROUND2(a, b, c, d, e, i)  \
    SCHEDULE(i)  \
    ROUNDTAIL(a, b, e, ((b & c) ^ (b & d) ^ (c & d)), i, 0x8F1BBCDC)

#define ROUND3(a, b, c, d, e, i)  \
    SCHEDULE(i)  \
    ROUNDTAIL(a, b, e, (b ^ c ^ d), i, 0xCA62C1D6)

void sha1_compress_software(uint32_t state[5], const uint8_t *data) {
    const uint32_t *block = (const uint32_t *) data;
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    uint32_t schedule[16];
    uint32_t temp;
    ROUND0a(a, b, c, d, e, 0)
    ROUND0a(e, a, b, c, d, 1)
    ROUND0a(d, e, a, b, c, 2)
    ROUND0a(c, d, e, a, b, 3)
    ROUND0a(b, c, d, e, a, 4)
    ROUND0a(a, b, c, d, e, 5)
    ROUND0a(e, a, b, c, d, 6)
    ROUND0a(d, e, a, b, c, 7)
    ROUND0a(c, d, e, a, b, 8)
    ROUND0a(b, c, d, e, a, 9)
    ROUND0a(a, b, c, d, e, 10)
    ROUND0a(e, a, b, c, d, 11)
    ROUND0a(d, e, a, b, c, 12)
    ROUND0a(c, d, e, a, b, 13)
    ROUND0a(b, c, d, e, a, 14)
    ROUND0a(a, b, c, d, e, 15)
    ROUND0b(e, a, b, c, d, 16)
    ROUND0b(d, e, a, b, c, 17)
    ROUND0b(c, d, e, a, b, 18)
    ROUND0b(b, c, d, e, a, 19)
    ROUND1(a, b, c, d, e, 20)
    ROUND1(e, a, b, c, d, 21)
    ROUND1(d, e, a, b, c, 22)
    ROUND1(c, d, e, a, b, 23)
    ROUND1(b, c, d, e, a, 24)
    ROUND1(a, b, c, d, e, 25)
    ROUND1(e, a, b, c, d, 26)
    ROUND1(d, e, a, b, c, 27)
    ROUND1(c, d, e, a, b, 28)
    ROUND1(b, c, d, e, a, 29)
    ROUND1(a, b, c, d, e, 30)
    ROUND1(e, a, b, c, d, 31)
    ROUND1(d, e, a, b, c, 32)
    ROUND1(c, d, e, a, b, 33)
    ROUND1(b, c, d, e, a, 34)
    ROUND1(a, b, c, d, e, 35)
    ROUND1(e, a, b, c, d, 36)
    ROUND1(d, e, a, b, c, 37)
    ROUND1(c, d, e, a, b, 38)
    ROUND1(b, c, d, e, a, 39)
    ROUND2(a, b, c, d, e, 40)
    ROUND2(e, a, b, c, d, 41)
    ROUND2(d, e, a, b, c, 42)
    ROUND2(c, d, e, a, b, 43)
    ROUND2(b, c, d, e, a, 44)
    ROUND2(a, b, c, d, e, 45)
    ROUND2(e, a, b, c, d, 46)
    ROUND2(d, e, a, b, c, 47)
    ROUND2(c, d, e, a, b, 48)
    ROUND2(b, c, d, e, a, 49)
    ROUND2(a, b, c, d, e, 50)
    ROUND2(e, a, b, c, d, 51)
    ROUND2(d, e, a, b, c, 52)
    ROUND2(c, d, e, a, b, 53)
    ROUND2(b, c, d, e, a, 54)
    ROUND2(a, b, c, d, e, 55)
    ROUND2(e, a, b, c, d, 56)
    ROUND2(d, e, a, b, c, 57)
    ROUND2(c, d, e, a, b, 58)
    ROUND2(b, c, d, e, a, 59)
    ROUND3(a, b, c, d, e, 60)
    ROUND3(e, a, b, c, d, 61)
    ROUND3(d, e, a, b, c, 62)
    ROUND3(c, d, e, a, b, 63)
    ROUND3(b, c, d, e, a, 64)
    ROUND3(a, b, c, d, e, 65)
    ROUND3(e, a, b, c, d, 66)
    ROUND3(d, e, a, b, c, 67)
    ROUND3(c, d, e, a, b, 68)
    ROUND3(b, c, d, e, a, 69)
    ROUND3(a, b, c, d, e, 70)
    ROUND3(e, a, b, c, d, 71)
    ROUND3(d, e, a, b, c, 72)
    ROUND3(c, d, e, a, b, 73)
    ROUND3(b, c, d, e, a, 74)
    ROUND3(a, b, c, d, e, 75)
    ROUND3(e, a, b, c, d, 76)
    ROUND3(d, e, a, b, c, 77)
    ROUND3(c, d, e, a, b, 78)
    ROUND3(b, c, d, e, a, 79)

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}
