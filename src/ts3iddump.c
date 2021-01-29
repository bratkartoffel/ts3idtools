#include "globals.h"
#include "base64.h"

#include <getopt.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>

static void print_usage(const char *name) {
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -h, --help             Print this usage information\n"
           "  -i, --identity=STRING  Identity (Starts with a number followed by a 'V')\n"
           "  -s, --secret           Also print out secret key (DO NOT SHARE THIS!)\n"
           "  -v, --verbose          Enable debug output\n"
           "\n"
           "WARNING: The secret key can be used to 'steal' your identity! Do not share this information with others!\n"
           "\n"
           "ts3idtools - v%s - created by bratkartoffel - Code at https://github.com/bratkartoffel/ts3idtools\n"
           "\n", name, VERSION);
}

static bool asn1_parse_integer(const unsigned char **asn1data_pos, long length, BIGNUM *bn_result) {
    debug_printf("> asn1_parse_integer(%p, %li, %p)\n",
                 (void *) asn1data_pos, length, (void *) bn_result);
    bool result = true;
    long len;
    int ret, tag, xclass;
    ret = ASN1_get_object(asn1data_pos, &len, &tag, &xclass, length);
    if (ret & 0x80) {
        fprintf(stderr, "ASN1_get_object() failed\n");
        result = false;
    }
    if (tag != V_ASN1_INTEGER) {
        fprintf(stderr, "Invalid tag for ASN1: %d (%s)\n", tag, ASN1_tag2str(tag));
        result = false;
    }
    if (result) {
        ASN1_INTEGER *temp = ASN1_INTEGER_new();
        if (!c2i_ASN1_INTEGER(&temp, asn1data_pos, len)) {
            fprintf(stderr, "d2i_ASN1_INTEGER() failed\n");
            result = false;
        }
        ASN1_INTEGER_to_BN(temp, bn_result);
        ASN1_INTEGER_free(temp);
    }

    debug_printf("< asn1_parse_integer(): %u\n", result);
    return result;
}

static bool asn1_parse(size_t asn1data_len, const uint8_t asn1data[asn1data_len],
                       BIGNUM *x, BIGNUM *y, BIGNUM *z) {
    debug_printf("> asn1_parse(%" PRIu64 ", %p, %p, %p, %p)\n",
                 asn1data_len, asn1data, (void *) x, (void *) y, (void *) z);
    const unsigned char *asn1data_pos = asn1data;
    long len, length = asn1data_len;
    int tag, xclass, ret;
    // SEQUENCE
    ret = ASN1_get_object(&asn1data_pos, &len, &tag, &xclass, length);
    if (ret & 0x80) {
        fprintf(stderr, "ASN1_get_object() failed\n");
        return false;
    }
    if (tag != V_ASN1_SEQUENCE) {
        fprintf(stderr, "(1) Invalid tag for ASN1: %d: %s\n", tag, ASN1_tag2str(tag));
        return false;
    }
    // BIT_STRING -- bitInfo, ignored for now
    ret = ASN1_get_object(&asn1data_pos, &len, &tag, &xclass, length);
    if (ret & 0x80) {
        fprintf(stderr, "ASN1_get_object() failed\n");
        return false;
    }
    if (tag != V_ASN1_BIT_STRING) {
        fprintf(stderr, "(2) Invalid tag for ASN1: %d: %s\n", tag, ASN1_tag2str(tag));
        return false;
    }
    ASN1_BIT_STRING *temp = ASN1_BIT_STRING_new();
    if (!c2i_ASN1_BIT_STRING(&temp, &asn1data_pos, len)) {
        fprintf(stderr, "d2i_ASN1_INTEGER() failed\n");
        return false;
    }
    ASN1_BIT_STRING_free(temp);

    BIGNUM *ignored = BN_new();
    asn1_parse_integer(&asn1data_pos, length, ignored);
    asn1_parse_integer(&asn1data_pos, length, x);
    asn1_parse_integer(&asn1data_pos, length, y);
    asn1_parse_integer(&asn1data_pos, length, z);

    // sanity check, everything parsed?
    if (*asn1data_pos != 0) {
        debug_printf("  asn1_parse: dangling data: %c\n", *asn1data_pos);
    }
    debug_printf("< asn1_parse(): 1\n");
    return true;
}

static bool validate_arguments(const char *identity_in) {
    debug_printf("> validate_arguments(%s)\n", identity_in);
    bool result = true;
    if (!identity_in) {
        fprintf(stderr, "Missing required argument: 'identity'\n");
        result = false;
    } else if (strlen(identity_in) > 256) {
        fprintf(stderr, "Invalid argument: 'identity' is too long\n");
        result = false;
    }
    debug_printf("< validate_arguments(): %u\n", result);
    return true;
}

static void print_arguments(const char *identity_in, bool print_secret) {
    debug_printf("> print_arguments(%s, %u)\n", identity_in, print_secret);
    debug_printf("  print_arguments: identity_in=%s\n", identity_in);
    debug_printf("  print_arguments: print_secret=%u\n", print_secret);
    debug_printf("< print_arguments()\n");
}

static bool deobfuscate_key(size_t identityData_len, uint8_t identityData[identityData_len]) {
    debug_printf("> deobfuscate_key(%" PRIu64 ", %p)\n",
                 identityData_len, identityData);
    bool result = true;
    uint8_t buffer[identityData_len];
    memcpy(buffer, identityData, identityData_len);

    uint8_t identityHash[SHA_DIGEST_LENGTH];
    {
        int nullIndex = -1;
        for (int i = 20; i < (int) identityData_len; i++) {
            if (buffer[i] == 0x0) {
                nullIndex = i - 20;
                break;
            }
        }
        debug_printf("  deobfuscate_key: nullIndex=%d\n", nullIndex);

        EVP_MD_CTX ctx;
        const EVP_MD *md = EVP_sha1();
        EVP_DigestInit(&ctx, md);
        EVP_DigestUpdate(&ctx, buffer + 20, nullIndex < 0 ? (int) identityData_len - 20 : nullIndex);
        EVP_DigestFinal(&ctx, identityHash, NULL);
        debug_print_hex("  deobfuscate_key: identityHash", identityHash, SHA_DIGEST_LENGTH);
    }

    if (!ts3_xor(identityData_len, buffer, 0,
                 20, identityHash, 0,
                 20,
                 identityData_len, buffer, 0)) {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  deobfuscate_key: round 1", buffer, identityData_len);

    if (!ts3_xor(identityData_len, buffer, 0,
                 OBFUSCATION_KEY_LEN, OBFUSCATION_KEY, 0,
                 identityData_len > 100 ? 100 : identityData_len,
                 identityData_len, buffer, 0)) {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  deobfuscate_key: round 2", buffer, identityData_len);

    bool null_found = false;
    for (size_t i = 0; i < identityData_len; i++) {
        if (buffer[i] == 0) {
            null_found = true;
            break;
        }
    }
    if (!null_found) {
        fprintf(stderr, "xor() failed, no null found\n");
        result = false;
    }

    if (result) {
        memcpy(identityData, buffer, identityData_len);
    }

    debug_printf("< deobfuscate_key(): %u\n", result);
    return result;
}

int main(int argc, const char *const *argv) {
    const char *identity_in = NULL;
    bool print_secret = false;

    static struct option long_options[] = {
            {"help",     no_argument,       0, 'h'},
            {"identity", required_argument, 0, 'i'},
            {"secret",   no_argument,       0, 's'},
            {"verbose",  no_argument,       0, 'v'},
            {0,          0,                 0, 0}
    };
    bool missing_value = false;
    int c;
    while ((c = getopt_long(argc, (char *const *) argv, "vhi:s", long_options, NULL)) != -1) {
        switch (c) {
            case 'h':
                print_usage(*argv);
                return 0;
            case 'i':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                identity_in = optarg;
                break;
            case 's':
                print_secret = true;
                break;
            case 'v':
                debug = true;
                break;
            default:
                fprintf(stderr, "Unknown option given: '%c'\n", c);
                break;
        }
    }

    if (missing_value) {
        print_usage(*argv);
        return 1;
    }

    if (!validate_arguments(identity_in)) {
        fprintf(stderr, "validate_arguments() failed\n");
        print_usage(*argv);
        return 1;
    }

    print_arguments(identity_in, print_secret);

    const char *match = strchr(identity_in, 'V');
    debug_printf("  main: match=%p\n", match);
    if (!match) {
        print_usage(*argv);
        fprintf(stderr, "Invalid argument: 'identity' has wrong format (no 'V' found)\n");
        return 1;
    }
    debug_printf("  main: match - identity_in=%p\n", (void *) (match - identity_in));
    if (match - identity_in == 0) {
        print_usage(*argv);
        fprintf(stderr, "Invalid argument: 'identity' has wrong format (no counter found)\n");
        return 1;
    }
    uint64_t counter;
    {
        char temp[match - identity_in + 1];
        memcpy(temp, identity_in, match - identity_in);
        temp[match - identity_in] = 0;
        counter = strtoll(temp, NULL, 10);
        debug_printf("  main: counter=%" PRIu64 "\n", counter);
    }

    size_t identity_len = strlen(match + 1);
    debug_printf("  main: identity_len=%" PRIu64 "\n", identity_len);
    if (identity_len < 190 || identity_len % 4 != 0) {
        print_usage(*argv);
        fprintf(stderr, "Invalid argument: 'identity' has wrong format (wrong length: %" PRIu64 ")\n", identity_len);
        return 1;
    }
    uint8_t identity[identity_len + 1];
    memcpy(identity, match + 1, identity_len);
    identity[identity_len] = 0;

    size_t identityData_len = base64_get_decode_length(identity_len);
    uint8_t identityData[identityData_len];
    if (!base64_decode(identity_len, identity, &identityData_len, identityData)) {
        fprintf(stderr, "base64_decode() failed\n");
        return 1;
    }

    if (!deobfuscate_key(identityData_len, identityData)) {
        fprintf(stderr, "obfuscate_key() failed\n");
        return 1;
    }

    size_t asn1data_len = base64_get_decode_length(identityData_len);
    uint8_t asn1data[asn1data_len];
    if (!base64_decode(identityData_len, identityData, &asn1data_len, asn1data)) {
        fprintf(stderr, "base64_decode() failed\n");
        return 1;
    }
    debug_print_hex("  main: asn1 data", identityData, identityData_len);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *z = BN_new();
    if (!asn1_parse(asn1data_len, asn1data, x, y, z)) {
        fprintf(stderr, "asn1_parse() failed\n");
        return 1;
    }

    size_t pubkey_len = PUBKEY_LEN_OBFUSCATED_B64;
    unsigned char pubkey[pubkey_len];
    create_pubkey(x, y, &pubkey_len, pubkey);

    size_t uuid_len = base64_get_encode_length(SHA_DIGEST_LENGTH);
    unsigned char uuid[uuid_len + 1];
    create_uuid(pubkey_len, pubkey, &uuid_len, uuid);

    printf("UUID=%s\n", uuid);
    printf("PublicKey=%s\n", pubkey);
    print_bignum("  x=%s\n", x);
    print_bignum("  y=%s\n", y);
    if (print_secret) {
        size_t privkey_len = PRIVKEY_LEN_OBFUSCATED_B64;
        uint8_t privkey[privkey_len + 1];
        memset(privkey, 0, privkey_len);
        create_privkey(x, y, z, &privkey_len, privkey);
        printf("PrivateKey=%s\n", privkey);
        print_bignum("  z=%s\n", z);
    }

    BN_free(x);
    BN_free(y);
    BN_free(z);

    printf("Counter=%" PRIu64 "\n", counter);
    printf("SecurityLevel=%u\n", get_security_level((const char *) pubkey, counter));
    return 0;
}
