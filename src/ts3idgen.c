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
#include <string.h>

#include "identity.h"

static void print_usage(const char* name)
{
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -h, --help             Print this usage information\n"
           "  -i, --name=STRING      Name of the generated identity\n"
           "                         Has to be at most 30 chars, defaults to 'New identity'\n"
           "  -l, --level=NUMBER     Minimum level for created identity\n"
           "                         Has to be between 4 and 12. For better values use the ts3idcrunch application.\n"
           "  -n, --nickname=STRING  Nickname for identity\n"
           "                         Has to be between 3 and 30 characters, defaults to 'anonymous'\n"
           "  -o, --output=FILE      Output filename\n"
           "                         If set to '-' then the identity will be printed to stdout\n"
           "  -v, --verbose          Enable debug output\n"
           "\n"
           "ts3idtools - v%s - created by bratkartoffel - Code at https://github.com/bratkartoffel/ts3idtools\n"
           "\n", name, VERSION);
}

static bool validate_arguments(const char* nickname, const char* name, const uint8_t level)
{
    debug_printf("> validate_arguments(%s, %s, %u)\n", nickname, name, level);
    bool result = true;
    if (strlen(nickname) < 3 || strlen(nickname) > 30)
    {
        fprintf(stderr, "Invalid argument: 'nickname' is too short or too long\n");
        result = false;
    }
    if (strlen(name) == 0 || strlen(name) > 30)
    {
        fprintf(stderr, "Invalid argument: 'alias' may not be empty\n");
        result = false;
    }
    if (level < 4 || level > 12)
    {
        fprintf(stderr, "Invalid argument: 'level' must be between 4 and 12\n");
        result = false;
    }
    debug_printf("< validate_arguments(): %u\n", result);
    return result;
}

static void print_arguments(const char* name, const char* nickname, const char* output_file, const uint8_t level)
{
    debug_printf("> print_arguments(%s, %s, %s)\n", nickname, name, output_file);
    debug_printf("  print_arguments: name=%s\n", name);
    debug_printf("  print_arguments: nickname=%s\n", nickname);
    debug_printf("  print_arguments: output_file=%s\n", output_file);
    debug_printf("  print_arguments: level=%u\n", level);
    debug_printf("< print_arguments()\n");
}

static EC_KEY* create_new_key()
{
    debug_printf("> create_new_key()\n");
    EC_KEY* ec_key = NULL;
    EC_GROUP* ec_group = NULL;

    ec_key = EC_KEY_new();
    debug_printf("  create_new_key: ec_key=%p\n", (void *) ec_key);
    if (!ec_key)
    {
        fprintf(stderr, "EC_KEY_new() failed\n");
        goto abort;
    }

    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    debug_printf("  create_new_key: ec_group=%p\n", (void *) ec_group);
    if (!ec_group)
    {
        fprintf(stderr, "EC_GROUP_new_by_curve_name() failed\n");
        goto abort;
    }

    debug_printf("  create_new_key: pre EC_KEY_set_group\n");
    if (!EC_KEY_set_group(ec_key, ec_group))
    {
        fprintf(stderr, "EC_KEY_set_group() failed\n");
        goto abort;
    }

    debug_printf("  create_new_key: pre EC_KEY_generate_key\n");
    if (!EC_KEY_generate_key(ec_key))
    {
        fprintf(stderr, "EC_KEY_generate_key() failed\n");
        goto abort;
    }

    EC_GROUP_free(ec_group);
    debug_printf("< create_new_key(): %p\n", (void *) ec_key);
    return ec_key;

abort:
    if (ec_group) EC_GROUP_free(ec_group);
    if (ec_key) EC_KEY_free(ec_key);
    debug_printf("< create_new_key(): %p\n", NULL);
    return NULL;
}

static void write_identity(const char* name, const char* nickname, const char* output_file,
                           uint64_t counter, const char* obfuscated)
{
    debug_printf("> write_identity(%s, %s, %s, %" PRIu64", %s)\n",
                 name, nickname, output_file, counter, obfuscated);
    FILE* fp;
    if (output_file[0] == '-' && output_file[1] == 0)
    {
        fp = stdout;
    }
    else
    {
        fp = fopen(output_file, "w");
        if (!fp)
        {
            fprintf(stderr, "fopen() failed: %i: %s\n", errno, strerror(errno));
        }
    }
    if (fp)
    {
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

static void increase_level_to_min(ts3_identity* identity, uint8_t target)
{
    debug_printf("> increase_level_to_min(%p)\n", (void*) identity);
    uint32_t state[5];
    uint8_t* data = calloc(128, sizeof(uint8_t));
    memcpy(data, identity->pubkey, identity->pubkey_len);

    do_sha1_first_block(data, state);
    uint32_t hash[5];
    uint64_t counter = 0;
    uint8_t level;
    debug_printf("  crunch: ");
    do
    {
        counter++;
        size_t data_len = append_counter(data, identity->pubkey_len, counter);
        do_sha1_second_block_without_cpu_ext(data, data_len, state, hash);
        level = leading_zero_bits(hash);
        if (counter % 10 == 0)
        {
            debug_printf(".");
        }
    }
    while (level < target);
    debug_printf("\n");

    identity->counter = counter;
    free(data);
    debug_printf("< increase_level_to_min(): %" PRIu64 "\n", counter);
}

int main(int argc, char** argv)
{
    const char* name = "New identity";
    const char* nickname = "anonymous";
    const char* output_file = "-";
    uint8_t level = 8;

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"name", required_argument, NULL, 'i'},
        {"level", required_argument, NULL, 'l'},
        {"nickname", required_argument, NULL, 'n'},
        {"output", required_argument, NULL, 'o'},
        {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0}
    };
    bool missing_value = false;
    int c;
    while ((c = getopt_long(argc, (char*const *)argv, "hi:n:o:vV", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'h':
            print_usage(*argv);
            return 0;
        case 'i':
            if (!optarg)
            {
                fprintf(stderr, "Value missing for option '%c'\n", c);
                missing_value = true;
                continue;
            }
            name = optarg;
            break;
        case 'l':
            if (!optarg)
            {
                fprintf(stderr, "Value missing for option '%c'\n", c);
                missing_value = true;
                continue;
            }
            level = strtol(optarg, NULL, 10);
            break;
        case 'n':
            if (!optarg)
            {
                fprintf(stderr, "Value missing for option '%c'\n", c);
                missing_value = true;
                continue;
            }
            nickname = optarg;
            break;
        case 'o':
            if (!optarg)
            {
                fprintf(stderr, "Value missing for option '%c'\n", c);
                missing_value = true;
                continue;
            }
            output_file = optarg;
            break;
        case 'v':
            debug = true;
            break;
        case 'V':
            printf("ts3idgen version %s\n", VERSION);
            return 0;
        default:
            fprintf(stderr, "Unknown option given: '%c'\n", optopt);
            break;
        }
    }

    if (missing_value)
    {
        print_usage(*argv);
        return 1;
    }

    if (!validate_arguments(nickname, name, level))
    {
        fprintf(stderr, "validate_arguments() failed\n");
        print_usage(*argv);
        return 1;
    }

    print_arguments(name, nickname, output_file, level);

    EC_KEY* ec_key = create_new_key();
    if (!ec_key)
    {
        fprintf(stderr, "create_new_key() failed\n");
        return 1;
    }

    const EC_POINT* ec_pub = EC_KEY_get0_public_key(ec_key);
    if (!ec_pub)
    {
        EC_KEY_free(ec_key);
        fprintf(stderr, "EC_KEY_get0_public_key() failed\n");
        return 1;
    }

    BIGNUM* x = BN_new();
    if (!x)
    {
        EC_KEY_free(ec_key);
        fprintf(stderr, "BN_new(x) failed\n");
        return 1;
    }
    BIGNUM* y = BN_new();
    if (!y)
    {
        EC_KEY_free(ec_key);
        BN_free(x);
        fprintf(stderr, "BN_new(y) failed\n");
        return 1;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ec_key), ec_pub, x, y, NULL))
    {
        EC_KEY_free(ec_key);
        BN_free(x);
        BN_free(y);
        fprintf(stderr, "EC_POINT_get_affine_coordinates_GFp() failed\n");
        return 1;
    }

    ts3_identity* id = calloc(1, sizeof(ts3_identity));
    if (!id)
    {
        EC_KEY_free(ec_key);
        BN_free(x);
        BN_free(y);
        fprintf(stderr, "calloc(id) failed\n");
        return 1;
    }

    if (!create_privkey(id, x, y, EC_KEY_get0_private_key(ec_key)))
    {
        EC_KEY_free(ec_key);
        BN_free(x);
        BN_free(y);
        fprintf(stderr, "create_privkey() failed\n");
        return 1;
    }
    EC_KEY_free(ec_key);

    if (!create_pubkey(id, x, y))
    {
        BN_free(x);
        BN_free(y);
        fprintf(stderr, "create_pubkey() failed\n");
        return 1;
    }
    BN_free(x);
    BN_free(y);

    if (!create_uuid(id))
    {
        fprintf(stderr, "create_uuid() failed\n");
        return 1;
    }

    increase_level_to_min(id, level);

    size_t encoded_len;
    char* encoded = encode_identity(id, &encoded_len);
    debug_printf("  main: encoded=%s\n", encoded);

    write_identity(name, nickname, output_file, id->counter, encoded);
    free(encoded);
    free_identity(id);
    free(id);

    fflush(stdout);
    return 0;
}
