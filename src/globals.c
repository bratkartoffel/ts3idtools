#include "globals.h"
#include "base64.h"

#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

bool debug = false;

size_t append_counter(uint8_t data[PUBKEY_LEN_B64], size_t length, uint64_t value) {
    // no debug logging, extremely performance sensitive!
    size_t result;
    if (value > 9999999999999999999UL) {
        result = 20;
    } else if (value > 999999999999999999UL) {
        result = 19;
    } else if (value > 99999999999999999UL) {
        result = 18;
    } else if (value > 9999999999999999UL) {
        result = 17;
    } else if (value > 999999999999999UL) {
        result = 16;
    } else if (value > 99999999999999UL) {
        result = 15;
    } else if (value > 9999999999999UL) {
        result = 14;
    } else if (value > 999999999999UL) {
        result = 13;
    } else if (value > 99999999999UL) {
        result = 12;
    } else if (value > 9999999999UL) {
        result = 11;
    } else if (value > 999999999UL) {
        result = 10;
    } else if (value > 99999999UL) {
        result = 9;
    } else if (value > 9999999UL) {
        result = 8;
    } else if (value > 999999UL) {
        result = 7;
    } else if (value > 99999UL) {
        result = 6;
    } else if (value > 9999UL) {
        result = 5;
    } else if (value > 999UL) {
        result = 4;
    } else if (value > 99UL) {
        result = 3;
    } else if (value > 9UL) {
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

size_t increment_counter(uint8_t data[PUBKEY_LEN_B64], size_t pubkey_length, size_t complete_length) {
    uint8_t *start_counter = data + pubkey_length;
    uint8_t *end_counter = data + complete_length;
    for (uint8_t *pos = end_counter - 1; pos >= start_counter; pos--) {
        if (*pos < '9') {
            *pos = *pos + 1;
            return complete_length;
        }
        *pos = '0';
    }
    *start_counter = '1';
    *end_counter = '0';
    return complete_length + 1;
}

uint8_t get_security_level(ts3_pubkey_t* pubkey, uint64_t counter) {
    debug_printf("> get_security_level(%s, %" PRIu64 ")\n",
                 pubkey, counter);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, pubkey, strlen((const char*) pubkey));
    char buffer[32];
    snprintf(buffer, 32, "%" PRIu64, counter);
    EVP_DigestUpdate(ctx, buffer, strlen(buffer));
    uint32_t hash[SHA_DIGEST_LENGTH/4];
    EVP_DigestFinal(ctx, (uint8_t*) hash, NULL);
    EVP_MD_CTX_free(ctx);
    debug_print_hex("  get_security_level: state", hash, SHA_DIGEST_LENGTH);
    const uint8_t result = leading_zero_bits(hash);
    debug_printf("< get_security_level(): %u\n", result);
    return result;
}

uint8_t leading_zero_bits(uint32_t hash[5]) {
    if (hash[0] == 0) {
        if (hash[1] == 0) {
            if (hash[2] == 0) {
                if (hash[3] == 0) {
                    if (hash[4] == 0) {
                        return 160;
                    }
                    return 128 + __builtin_ctz(hash[4]);
                }
                return 96 + __builtin_ctz(hash[3]);
            }
            return 64 + __builtin_ctz(hash[2]);
        }
        return 32 + __builtin_ctz(hash[1]);
    }
    return __builtin_ctz(hash[0]);
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
                   size_t *pubkey_len, ts3_pubkey_t pubkey[*pubkey_len]) {
    debug_printf("> create_pubkey(%p, %p, %" PRIu64 ", %p)\n",
                 (void *) x, (void *) y, *pubkey_len, pubkey);
    uint8_t buffer[512];

    // start sequence
    buffer[0] = 0x30;

    // length of sequence, unknown yet
    buffer[1] = 0x00;

    // fixed bitstring
    buffer[2] = 0x03;  // bitstring
    buffer[3] = 0x02;  // length
    buffer[4] = 0x07;  // value
    buffer[5] = 0x00;

    // fixed integer
    buffer[6] = 0x02;  // integer
    buffer[7] = 0x01;  // length
    buffer[8] = 0x20;  // value

    // currently at index 9
    size_t buffer_pos = 9;
    {
        // write X
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(x, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
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
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
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
                    size_t *privkey_len, ts3_privkey_t privkey[*privkey_len]) {
    debug_printf("> create_privkey(%p, %p, %p, %" PRIu64 ", %p)\n",
                 (void *) x, (void *) y, (void *) z, *privkey_len, privkey);
    uint8_t buffer[512];

    // start sequence
    buffer[0] = 0x30;

    // length of sequence, unknown yet
    buffer[1] = 0x00;

    // fixed bitstring
    buffer[2] = 0x03;
    buffer[3] = 0x02;
    buffer[4] = 0x07;
    buffer[5] = 0x80;

    // fixed integer
    buffer[6] = 0x02;
    buffer[7] = 0x01;
    buffer[8] = 0x20;

    // currently at index 9
    size_t buffer_pos = 9;
    {
        // write x
        uint8_t *temp = buffer + buffer_pos;
        ASN1_INTEGER *asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(x, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
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
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
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
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
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

void create_uuid(size_t pubkey_len, ts3_pubkey_t pubkey[pubkey_len],
                 size_t *uuid_len, ts3_uuid_t uuid[*uuid_len]) {
    debug_printf("> create_uuid(%" PRIu64 ", %p, %" PRIu64 ", %p)\n",
                 pubkey_len, pubkey, *uuid_len, uuid);
    uint8_t hash[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
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
