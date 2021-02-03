#ifdef NDEBUG
#  undef NDEBUG
#endif

#include <assert.h>

#include "globals.h"
#include "sha1.h"

void testSha1SingleRound() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t data[128] = {0};
    strcpy((char *) data, "this is just a one block example");
    uint32_t state[5];
    do_sha1_first_block(data, state);

    uint32_t expected[5] = {
            4156553573,
            2192141954,
            2271538046,
            2679903082,
            2727190866
    };

    debug_print_hex("expected", expected, SHA_DIGEST_LENGTH);
    debug_print_hex("  actual", state, SHA_DIGEST_LENGTH);
    assert(memcmp(state, expected, SHA_DIGEST_LENGTH) == 0);
}

void testAppendCounter() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t data[128] = {0};
    strcpy((char *) data, "foobar");
    size_t len = append_counter(data, 6, 42L);
    debug_print_hex("data", data, len);
    assert(len == 8);
    assert(memcmp(data, "foobar42", len) == 0);
}

void testIncrementCounterSimple() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t data[128] = {0};
    strcpy((char *) data, "foobar42");
    size_t len = increment_counter(data, 6, 8);
    debug_print_hex("data", data, len);
    assert(len == 8);
    assert(memcmp(data, "foobar43", 8) == 0);
}

void testIncrementCounterRollTen() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t data[128] = {0};
    strcpy((char *) data, "foobar49");
    size_t len = increment_counter(data, 6, 8);
    debug_print_hex("data", data, len);
    assert(len == 8);
    assert(memcmp(data, "foobar50", 8) == 0);
}

void testIncrementCounterNewDigit() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t data[128] = {0};
    strcpy((char *) data, "foobar99");
    size_t len = increment_counter(data, 6, 8);
    debug_print_hex("data", data, len);
    assert(len == 9);
    assert(memcmp(data, "foobar100", 9) == 0);
}

void testSha1SameResults() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t data[128] = {0};
    strcpy((char *) data, "foobar");
    uint32_t state[5] = {0};
    uint32_t hashWithoutCpuExt[5] = {0};
    uint32_t hashWithCpuExt[5] = {0};
    do_sha1_first_block(data, state);
    do_sha1_second_block_without_cpu_ext(data, 6, state, hashWithoutCpuExt);
    do_sha1_second_block_with_cpu_ext(data, 6, state, hashWithCpuExt);

    debug_print_hex("software", hashWithoutCpuExt, SHA_DIGEST_LENGTH);
    debug_print_hex("     cpu", hashWithCpuExt, SHA_DIGEST_LENGTH);
    assert(memcmp(hashWithoutCpuExt, hashWithCpuExt, SHA_DIGEST_LENGTH) == 0);
}

void testGetSecurityLevel() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t level = get_security_level(
            "MEsDAgcAAgEgAiBuIdUrjo1z1DaVpq3uX6ugIOr1x7SS5cJbRiQo00QSUwIgRHSOqVqqkW8a1cYvrXmnvh3JSeMI/POWg3KvOXjnOUU=",
            351);

    debug_printf("level=%u\n", level);
    assert(level == 8);
}

void testGetSecurityLevelOver32() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint8_t level = get_security_level(
            "MEsDAgcAAgEgAiBuIdUrjo1z1DaVpq3uX6ugIOr1x7SS5cJbRiQo00QSUwIgRHSOqVqqkW8a1cYvrXmnvh3JSeMI/POWg3KvOXjnOUU=",
            22023984812);

    debug_printf("level=%u\n", level);
    assert(level == 37);
}

void testOneCrunchRound() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint64_t counter = 22023984812;
    uint8_t pubkey[128] = {0};
    size_t len = 104;
    uint32_t state[5] = {0};
    uint32_t hash[5] = {0};
    strncpy((char *) pubkey,
            "MEsDAgcAAgEgAiBuIdUrjo1z1DaVpq3uX6ugIOr1x7SS5cJbRiQo00QSUwIgRHSOqVqqkW8a1cYvrXmnvh3JSeMI/POWg3KvOXjnOUU=",
            len + 1);
    len = append_counter(pubkey, len, counter);
    debug_print_hex("data", pubkey, len);
    do_sha1_first_block(pubkey, state);
    debug_print_hex("state", state, SHA_DIGEST_LENGTH);
    do_sha1_second_block_without_cpu_ext(pubkey, len, state, hash);
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    uint8_t level = leading_zero_bits(hash);

    debug_printf("level=%u\n", level);
    assert(level == 37);
}

void testLeadingZeroBitsSkipSmaller8() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint32_t hash[5] = {0x80FFFFFF};
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    uint8_t bits = leading_zero_bits(hash);
    debug_printf("bits=%u\n", bits);
    assert(bits == 0);
}

void testLeadingZeroBits9() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint32_t hash[5] = {0x00FEFFFF};
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    uint8_t bits = leading_zero_bits(hash);
    debug_printf("bits=%u\n", bits);
    assert(bits == 9);
}

void testLeadingZeroBits160() {
    fprintf(stderr, "Starting %s\n", __func__);
    uint32_t hash[5] = {0};
    debug_print_hex("hash", hash, SHA_DIGEST_LENGTH);
    uint8_t bits = leading_zero_bits(hash);
    debug_printf("bits=%u\n", bits);
    assert(bits == 160);
}

int main(int argc, const char **argv) {
    ((void) argc);
    ((void) argv);
    debug = true;
    testSha1SingleRound();
    testAppendCounter();
    testIncrementCounterSimple();
    testIncrementCounterRollTen();
    testIncrementCounterNewDigit();
    testSha1SameResults();
    testGetSecurityLevel();
    testGetSecurityLevelOver32();
    testLeadingZeroBitsSkipSmaller8();
    testLeadingZeroBits9();
    testLeadingZeroBits160();
    testOneCrunchRound();
    return 0;
}
