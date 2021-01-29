#include "globals.h"
#include "base64.h"
#include "sha1.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <stdio.h>

static void print_usage(const char *name) {
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -h, --help             Print this usage information\n"
           "  -i, --name=STRING      Name of the generated identity\n"
           "                         Has to be at most 30 chars, defaults to 'New identity'\n"
           "  -n, --nickname=STRING  Nickname for identity\n"
           "                         Has to be between 3 and 30 characters, defaults to 'anonymous'\n"
           "  -o, --output=FILE      Output filename\n"
           "                         If set to '-' then the identity will be printed to stdout\n"
           "  -v, --verbose          Enable debug output\n"
           "\n"
           "ts3idtools - v%s - created by bratkartoffel - Code at https://github.com/bratkartoffel/ts3idtools\n"
           "\n", name, VERSION);
}

static bool validate_arguments(const char *nickname, const char *name) {
    debug_printf("> validate_arguments(%s, %s)\n",
                 nickname, name);
    bool result = true;
    if (strlen(nickname) < 3 || strlen(nickname) > 30) {
        fprintf(stderr, "Invalid argument: 'nickname' is too short or too long\n");
        result = false;
    }
    if (strlen(name) == 0 || strlen(name) > 30) {
        fprintf(stderr, "Invalid argument: 'alias' may not be empty\n");
        result = false;
    }
    debug_printf("< validate_arguments(): %u\n", result);
    return result;
}

static void print_arguments(const char *name, const char *nickname, const char *output_file) {
    debug_printf("> print_arguments(%s, %s, %s)\n", nickname, name, output_file);
    debug_printf("  print_arguments: name=%s\n", name);
    debug_printf("  print_arguments: nickname=%s\n", nickname);
    debug_printf("  print_arguments: output_file=%s\n", output_file);
    debug_printf("< print_arguments()\n");
}

static EC_KEY *create_new_key() {
    debug_printf("> create_new_key()\n");
    EC_KEY *ec_key = EC_KEY_new();

    debug_printf("  create_new_key: ec_key=%p\n", (void *) ec_key);
    if (!ec_key) {
        fprintf(stderr, "EC_KEY_new() failed\n");
        goto abort;
    }

    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    debug_printf("  create_new_key: ec_group=%p\n", (void *) ec_group);
    if (!ec_group) {
        fprintf(stderr, "EC_GROUP_new_by_curve_name() failed\n");
        goto abort;
    }

    debug_printf("  create_new_key: pre EC_KEY_set_group\n");
    if (!EC_KEY_set_group(ec_key, ec_group)) {
        fprintf(stderr, "EC_KEY_set_group() failed\n");
        goto abort;
    }

    debug_printf("  create_new_key: pre EC_KEY_generate_key\n");
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "EC_KEY_generate_key() failed\n");
        goto abort;
    }

    debug_printf("< create_new_key(): %p\n", (void *) ec_key);
    return ec_key;

    abort:
    EC_KEY_free(ec_key);
    debug_printf("< create_new_key(): %p\n", NULL);
    return NULL;
}

static void write_identity(const char *name, const char *nickname, const char *output_file,
                           uint64_t counter, const unsigned char *obfuscated) {
    debug_printf("> write_identity(%s, %s, %s, %" PRIu64", %s)\n",
                 name, nickname, output_file, counter, obfuscated);
    FILE *fp;
    if (output_file[0] == '-' && output_file[1] == 0) {
        fp = stdout;
    } else {
        fp = fopen(output_file, "w");
        if (!fp) {
            fprintf(stderr, "fopen() failed: %i: %s\n", errno, strerror(errno));
        }
    }
    if (fp) {
        fprintf(fp, "[Identity]\n"
                    "id=%s\n"
                    "identity=\"%" PRIu64 "V%s\"\n"
                    "nickname=%s\n",
                name,
                counter, obfuscated,
                nickname);
        if (fp != stdout) fclose(fp);
    }
    debug_printf("< write_identity()\n");
}

static bool obfuscate_key(size_t privkey_len, uint8_t privkey[privkey_len]) {
    debug_printf("> obfuscate_key(%" PRIu64 ", %p)\n",
                 privkey_len, privkey);
    bool result = true;
    uint8_t buffer[privkey_len];
    memcpy(buffer, privkey, privkey_len);

    if (!ts3_xor(privkey_len, buffer, 0,
                 OBFUSCATION_KEY_LEN, OBFUSCATION_KEY, 0,
                 privkey_len > 100 ? 100 : privkey_len,
                 privkey_len, buffer, 0)) {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  obfuscate_key: round 1", buffer, privkey_len);

    uint8_t identityHash[SHA_DIGEST_LENGTH];
    {
        int nullIndex = -1;
        for (int i = 20; i < (int) privkey_len; i++) {
            if (buffer[i] == 0x0) {
                nullIndex = i - 20;
                break;
            }
        }
        debug_printf("  obfuscate_key: nullIndex=%d\n", nullIndex);

        EVP_MD_CTX ctx;
        const EVP_MD *md = EVP_sha1();
        EVP_DigestInit(&ctx, md);
        EVP_DigestUpdate(&ctx, buffer + 20, nullIndex < 0 ? (int) privkey_len - 20 : nullIndex);
        EVP_DigestFinal(&ctx, identityHash, NULL);
        debug_print_hex("  obfuscate_key: identityHash", identityHash, SHA_DIGEST_LENGTH);
    }

    if (!ts3_xor(privkey_len, buffer, 0,
                 20, identityHash, 0,
                 20,
                 privkey_len, buffer, 0)) {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  obfuscate_key: round 2", buffer, privkey_len);

    if (result) {
        memcpy(privkey, buffer, privkey_len);
    }

    debug_printf("< obfuscate_key(): %u\n", result);
    return result;
}

static uint64_t increase_level_to_min(size_t pubkey_len, uint8_t *pubkey) {
    debug_printf("> increase_level_to_min(%" PRIu64 ", %p)\n", pubkey_len, pubkey);
    uint32_t state[5] __attribute__((aligned (16)));
    do_sha1_first_block(pubkey, state);
    uint8_t hash[SHA_DIGEST_LENGTH] = {0xFF};
    uint64_t counter = 0;
    uint8_t level;
    do {
        counter++;
        size_t data_len = append_counter(pubkey, pubkey_len, counter);
        do_sha1_second_block_software(pubkey, data_len, state, hash);
        level = leading_zero_bits(hash, 0);
        debug_printf("  increase_level_to_min: counter=%" PRIu64 ", level=%u\n", counter, level);
    } while (level < 8);

    debug_printf("< increase_level_to_min(): %" PRIu64 "\n", counter);
    return counter;
}

int main(int argc, const char *const *argv) {
    const char *name = "New identity";
    const char *nickname = "anonymous";
    const char *output_file = "-";

    static struct option long_options[] = {
            {"help",     no_argument,       0, 'h'},
            {"name",     required_argument, 0, 'i'},
            {"nickname", required_argument, 0, 'n'},
            {"output",   required_argument, 0, 'o'},
            {"verbose",  no_argument,       0, 'v'},
            {0,          0,                 0, 0}
    };
    bool missing_value = false;
    int c;
    while ((c = getopt_long(argc, (char *const *) argv, "hi:n:o:v", long_options, NULL)) != -1) {
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
                name = optarg;
                break;
            case 'n':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                nickname = optarg;
                break;
            case 'o':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                output_file = optarg;
                break;
            case 'v':
                debug = true;
                break;
            default:
                fprintf(stderr, "Unknown option given: '%c'\n", optopt);
                break;
        }
    }

    if (missing_value) {
        print_usage(*argv);
        return 1;
    }

    if (!validate_arguments(nickname, name)) {
        fprintf(stderr, "validate_arguments() failed\n");
        print_usage(*argv);
        return 1;
    }

    print_arguments(name, nickname, output_file);

    EC_KEY *ec_key = create_new_key();
    if (!ec_key) {
        fprintf(stderr, "create_new_key() failed\n");
        return 1;
    }

    const EC_POINT *ec_pub = EC_KEY_get0_public_key(ec_key);
    if (!ec_pub) {
        fprintf(stderr, "EC_KEY_get0_public_key() failed\n");
        return 1;
    }

    BIGNUM *x = BN_new();
    if (!x) {
        fprintf(stderr, "BN_new(x) failed\n");
        return 1;
    }
    BIGNUM *y = BN_new();
    if (!y) {
        fprintf(stderr, "BN_new(y) failed\n");
        return 1;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ec_key), ec_pub, x, y, NULL)) {
        fprintf(stderr, "EC_POINT_get_affine_coordinates_GFp() failed\n");
        return 1;
    }

    size_t pubkey_len = PUBKEY_LEN_OBFUSCATED_B64;
    uint8_t pubkey[pubkey_len + 1];
    memset(pubkey, 0, pubkey_len);
    create_pubkey(x, y, &pubkey_len, pubkey);
    debug_printf("  main: pubkey=%s\n", pubkey);

    size_t uuid_len = base64_get_encode_length(SHA_DIGEST_LENGTH);
    unsigned char uuid[uuid_len + 1];
    create_uuid(pubkey_len, pubkey, &uuid_len, uuid);
    debug_printf("  main: uuid=%s\n", uuid);

    uint64_t counter = increase_level_to_min(pubkey_len, pubkey);

    size_t privkey_len = PRIVKEY_LEN_OBFUSCATED_B64;
    uint8_t privkey[privkey_len + 1];
    memset(privkey, 0, privkey_len);
    create_privkey(x, y, EC_KEY_get0_private_key(ec_key), &privkey_len, privkey);
    debug_printf("  main: privkey=%s\n", privkey);

    if (!obfuscate_key(privkey_len, privkey)) {
        fprintf(stderr, "obfuscate_key() failed\n");
        return 1;
    }

    size_t obfuscated_len = base64_get_encode_length(privkey_len);
    unsigned char obfuscated[obfuscated_len + 1];
    base64_encode(privkey_len, privkey, &obfuscated_len, obfuscated);
    debug_printf("  main: obfuscated=%s\n", obfuscated);

    write_identity(name, nickname, output_file, counter, obfuscated);

    BN_free(y);
    BN_free(x);
    EC_KEY_free(ec_key);

    fflush(stdout);
    return 0;
}
