#include "globals.h"
#include "base64.h"

#include <inttypes.h>
#include <math.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

bool debug = false;

size_t append_counter(uint8_t data[128], size_t length, uint64_t value) {
    // no debug logging, extremely performance sensitive!
    size_t result;
    if (value > 99999999999999999L) {
        result = 18;
    } else if (value > 9999999999999999L) {
        result = 17;
    } else if (value > 999999999999999L) {
        result = 16;
    } else if (value > 99999999999999L) {
        result = 15;
    } else if (value > 9999999999999L) {
        result = 14;
    } else if (value > 999999999999L) {
        result = 13;
    } else if (value > 99999999999L) {
        result = 12;
    } else if (value > 9999999999L) {
        result = 11;
    } else if (value > 999999999L) {
        result = 10;
    } else if (value > 99999999L) {
        result = 9;
    } else if (value > 9999999L) {
        result = 8;
    } else if (value > 999999L) {
        result = 7;
    } else if (value > 99999L) {
        result = 6;
    } else if (value > 9999L) {
        result = 5;
    } else if (value > 999L) {
        result = 4;
    } else if (value > 99L) {
        result = 3;
    } else if (value > 9L) {
        result = 2;
    } else {
        result = 1;
    }

    for (uint8_t i = result - 1; i > 0; i--) {
        data[length + i] = (0x30 + (value % 10));
        value /= 10;
    }
    data[length] = (0x30 + value);
    return result + length;
}

size_t increment_counter(uint8_t data[128], size_t pubkey_length, size_t complete_length) {
    uint8_t *start_counter = data + pubkey_length;
    uint8_t *end_counter = data + complete_length;
    for (uint8_t *pos = end_counter - 1; pos >= start_counter; pos--) {
        if (*pos < '9') {
            *pos = *pos + 1;
            return complete_length;
        } else {
            *pos = '0';
        }
    }
    *start_counter = '1';
    *end_counter = '0';
    return complete_length + 1;
}

uint8_t get_security_level(const char *pubkey, uint64_t counter) {
    debug_printf("> get_security_level(%s, %" PRIu64 ")\n",
                 pubkey, counter);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, pubkey, strlen(pubkey));
    char buffer[32];
    snprintf(buffer, 32, "%" PRIu64, counter);
    EVP_DigestUpdate(ctx, buffer, strlen(buffer));
    uint8_t hash[SHA_DIGEST_LENGTH];
    EVP_DigestFinal(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    // store as big-endian
    uint32_t state[5] = {
            hash[0] << 24 | hash[1] << 16 | hash[2] << 8 | hash[3],
            hash[4] << 24 | hash[5] << 16 | hash[6] << 8 | hash[7],
            hash[8] << 24 | hash[9] << 16 | hash[10] << 8 | hash[11],
            hash[12] << 24 | hash[13] << 16 | hash[14] << 8 | hash[15],
            hash[16] << 24 | hash[17] << 16 | hash[18] << 8 | hash[19]
    };
    debug_print_hex("  get_security_level: state", hash, SHA_DIGEST_LENGTH);
    uint8_t result = leading_zero_bits(state);
    debug_printf("< get_security_level(): %u\n", result);
    return result;
}

uint8_t leading_zero_bits(const uint32_t hash[5]) {
    // no debug logging, extremely performance sensitive!

#define check_partial_byte(x)                     \
    do {                                          \
        if ((h[x] & 0x7F) == 0) return curr + 7;  \
        if ((h[x] & 0x3F) == 0) return curr + 6;  \
        if ((h[x] & 0x1F) == 0) return curr + 5;  \
        if ((h[x] & 0x0F) == 0) return curr + 4;  \
        if ((h[x] & 0x07) == 0) return curr + 3;  \
        if ((h[x] & 0x03) == 0) return curr + 2;  \
        if ((h[x] & 0x01) == 0) return curr + 1;  \
        return curr;                              \
    } while(0)

    uint8_t *h = (uint8_t *) hash;
    uint8_t curr = 0;

    if (h[3] == 0) curr += 8; else return 0;
    if (h[2] == 0) curr += 8; else check_partial_byte(2);
    if (h[1] == 0) curr += 8; else check_partial_byte(1);
    if (h[0] == 0) curr += 8; else check_partial_byte(0);

    if (h[7] == 0) curr += 8; else check_partial_byte(7);
    if (h[6] == 0) curr += 8; else check_partial_byte(6);
    if (h[5] == 0) curr += 8; else check_partial_byte(5);
    if (h[4] == 0) curr += 8; else check_partial_byte(4);

    if (h[11] == 0) curr += 8; else check_partial_byte(11);
    if (h[10] == 0) curr += 8; else check_partial_byte(10);
    if (h[9] == 0) curr += 8; else check_partial_byte(9);
    if (h[8] == 0) curr += 8; else check_partial_byte(8);

    if (h[15] == 0) curr += 8; else check_partial_byte(15);
    if (h[14] == 0) curr += 8; else check_partial_byte(14);
    if (h[13] == 0) curr += 8; else check_partial_byte(13);
    if (h[12] == 0) curr += 8; else check_partial_byte(12);

    if (h[19] == 0) curr += 8; else check_partial_byte(19);
    if (h[18] == 0) curr += 8; else check_partial_byte(18);
    if (h[17] == 0) curr += 8; else check_partial_byte(17);
    if (h[16] == 0) curr += 8; else check_partial_byte(16);

#undef check_partial_byte

    return curr;
}

bool ts3_xor(size_t a_len, const uint8_t *a, int aoffs,
             size_t b_len, const uint8_t *b, int boffs,
             size_t len,
             size_t outBuf_len, uint8_t *outBuf, int outOffs) {
    debug_printf("> ts3_xor(%" PRIu64 ", %p, %i, %" PRIu64 ", %p, %i, %" PRIu64 ", %" PRIu64 ", %p, %i)\n",
                 a_len, (void *) a, aoffs, b_len, (void *) b, boffs, len, outBuf_len, (void *) outBuf, outOffs);
    bool result = false;
    if (a_len >= len && b_len >= len && outBuf_len >= len) {
        for (size_t i = 0; i < len; i++) {
            outBuf[i + outOffs] = (uint8_t) (a[i + aoffs] ^ b[i + boffs]);
        }
        result = true;
    }
    debug_printf("< ts3_xor(): %u\n", result);
    return result;
}

void create_pubkey(const BIGNUM *x, const BIGNUM *y,
                   size_t *pubkey_len, unsigned char pubkey[*pubkey_len]) {
    debug_printf("> create_pubkey(%p, %p, %" PRIu64 ", %p)\n",
                 (void *) x, (void *) y, *pubkey_len, pubkey);
    size_t buffer_pos;
    uint8_t buffer[1024];

    // start sequence
    buffer[0] = 48;

    // length of sequence, unknown yet
    buffer[1] = 0;

    // fixed bitstring
    buffer[2] = 3;
    buffer[3] = 2;
    buffer[4] = 7;
    buffer[5] = 0;

    // fixed integer
    buffer[6] = 2;
    buffer[7] = 1;
    buffer[8] = 32;

    // currently at index 9
    buffer_pos = 9;
    {
        // write X
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(x, asn1);
        int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_pubkey: asn1(x)", buffer + buffer_pos, size);
        debug_printf("  create_pubkey: size(x)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }
    {
        // write X
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(y, asn1);
        int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_pubkey: asn1(y)", buffer + buffer_pos, size);
        debug_printf("  create_pubkey: size(y)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }

    // set length of sequence; excluding start tag and length itself
    buffer[1] = buffer_pos - 2;
    debug_printf("  create_pubkey: buffer_pos=%" PRIu64 "\n", buffer_pos);
    debug_printf("  create_pubkey: seq_length=%u\n", buffer[1]);
    base64_encode(buffer_pos, buffer, pubkey_len, pubkey);
    debug_printf("< create_pubkey(-, -, %" PRIu64 ", -)\n", *pubkey_len);
}

void create_privkey(const BIGNUM *x, const BIGNUM *y, const BIGNUM *z,
                    size_t *privkey_len, unsigned char privkey[*privkey_len]) {
    debug_printf("> create_privkey(%p, %p, %p, %" PRIu64 ", %p)\n",
                 (void *) x, (void *) y, (void *) z, *privkey_len, privkey);
    size_t buffer_pos;
    uint8_t buffer[1024];

    // start sequence
    buffer[0] = 48;

    // length of sequence, unknown yet
    buffer[1] = 0;

    // fixed bitstring
    buffer[2] = 3;
    buffer[3] = 2;
    buffer[4] = 7;
    buffer[5] = 128;

    // fixed integer
    buffer[6] = 2;
    buffer[7] = 1;
    buffer[8] = 32;

    // currently at index 9
    buffer_pos = 9;
    {
        // write x
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(x, asn1);
        int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_privkey: asn1(x)", buffer + buffer_pos, size);
        debug_printf("  create_privkey: size(x)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }
    {
        // write y
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(y, asn1);
        int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_privkey: asn1(y)", buffer + buffer_pos, size);
        debug_printf("  create_privkey: size(x)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }
    {
        // write z
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(z, asn1);
        int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_privkey: asn1(z)", buffer + buffer_pos, size);
        debug_printf("  create_privkey: size(x)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }

    // set length of sequence
    buffer[1] = buffer_pos - 2;
    debug_printf("  create_privkey: buffer_pos=%" PRIu64 "\n", buffer_pos);
    debug_printf("  create_pubkey: seq_length=%u\n", buffer[1]);
    base64_encode(buffer_pos, buffer, privkey_len, privkey);
    debug_printf("< create_privkey(-, -, %" PRIu64 ", -)\n", *privkey_len);
}

void create_uuid(size_t pubkey_len, const unsigned char pubkey[pubkey_len],
                 size_t *uuid_len, unsigned char uuid[*uuid_len]) {
    debug_printf("> create_uuid(%" PRIu64 ", %p, %" PRIu64 ", %p)\n",
                 pubkey_len, pubkey, *uuid_len, uuid);
    uint8_t hash[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new() failed\n");
        return;
    }
    const EVP_MD *md = EVP_sha1();
    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, pubkey, pubkey_len);
    EVP_DigestFinal(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    debug_print_hex("  create_uuid: hash", hash, SHA_DIGEST_LENGTH);
    base64_encode(SHA_DIGEST_LENGTH, hash, uuid_len, uuid);
    debug_printf("< create_uuid(-, -, %" PRIu64 ", -)\n", *uuid_len);
}

void print_bignum(const char *format, const BIGNUM *num) {
    char *hex = BN_bn2hex(num);
    printf(format, hex);
    OPENSSL_free(hex);
}

/* do not delete, needed to correctly link libressl with LTO */
char *strndup(const char *str, size_t maxlen) {
    char *copy;
    size_t len;

    len = strnlen(str, maxlen);
    copy = malloc(len + 1);
    if (copy != NULL) {
        (void) memcpy(copy, str, len);
        copy[len] = '\0';
    }

    return copy;
}

/* Check the CPUID bit for the availability of the Intel SHA Extensions */
bool check_for_intel_sha_extensions() {
    debug_printf("> check_for_intel_sha_extensions()\n");
    int a, b, c, d;

    /* Look for CPUID.7.0.EBX[29]
     * EAX = 7, ECX = 0 */
    a = 7;
    c = 0;

    asm volatile ("cpuid"
    :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
    :"a"(a), "c"(c)
    );

    /* SHA feature bit is EBX[29] */
    bool result = (b >> 29) & 1;

    debug_printf("< check_for_intel_sha_extensions(): %u\n", result);
    return result;
}
