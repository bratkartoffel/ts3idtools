#include "globals.h"
#include "base64.h"

#include <getopt.h>
#include <inttypes.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include "identity.h"


static void print_usage(const char* name)
{
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -h, --help             Print this usage information\n"
           "  -i, --identity=STRING  Identity (Starts with a number followed by a 'V')\n"
           "  -s, --secret           Also print out secret key (DO NOT SHARE THIS!)\n"
           "  -v, --verbose          Enable debug output\n"
           "  -V, --version          Print version information\n"
           "\n"
           "WARNING: The secret key can be used to 'steal' your identity! Do not share this information with others!\n"
           "\n"
           "ts3idtools - v%s - created by bratkartoffel - Code at https://github.com/bratkartoffel/ts3idtools\n"
           "\n", name, VERSION);
}

static bool validate_arguments(const char* identity_in)
{
    debug_printf("> validate_arguments(%s)\n", identity_in);
    bool result = true;
    if (!identity_in)
    {
        fprintf(stderr, "Missing required argument: 'identity'\n");
        result = false;
    }
    else if (strlen(identity_in) > 256)
    {
        fprintf(stderr, "Invalid argument: 'identity' is too long\n");
        result = false;
    }
    debug_printf("< validate_arguments(): %u\n", result);
    return result;
}

static void print_arguments(const char* identity_in, bool print_secret)
{
    debug_printf("> print_arguments(%s, %u)\n", identity_in, print_secret);
    debug_printf("  print_arguments: identity_in=%s\n", identity_in);
    debug_printf("  print_arguments: print_secret=%u\n", print_secret);
    debug_print("< print_arguments\n");
}

int main(int argc, char** argv)
{
    char* identity_in = NULL;
    bool print_secret = false;

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"identity", required_argument, NULL, 'i'},
        {"secret", no_argument, NULL, 's'},
        {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0}
    };
    bool missing_value = false;
    int c;
    while ((c = getopt_long(argc, argv, "hi:svV", long_options, NULL)) != -1)
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
            identity_in = optarg;
            break;
        case 's':
            print_secret = true;
            break;
        case 'v':
            debug = true;
            break;
        case 'V':
            printf("ts3iddump version %s\n", VERSION);
            return 0;
        default:
            fprintf(stderr, "Unknown option given: '%c'\n", c);
            break;
        }
    }

    if (missing_value)
    {
        print_usage(*argv);
        return 1;
    }

    if (!validate_arguments(identity_in))
    {
        fprintf(stderr, "validate_arguments() failed\n");
        print_usage(*argv);
        return 1;
    }

    print_arguments(identity_in, print_secret);

    ts3_identity id = {0};
    if (!decode_identity(identity_in, &id))
    {
        free_identity(&id);
        fprintf(stderr, "Failed to parse identity\n");
        return 1;
    }

    char* uuid_str = strndup((char*)id.uuid, id.uuid_len);
    printf("UUID=%s\n", uuid_str);
    free(uuid_str);

    char* pubkey_str = strndup((char*)id.pubkey, id.pubkey_len);
    printf("PublicKey=%s\n", pubkey_str);
    free(pubkey_str);

    if (print_secret)
    {
        char* privkey_str = strndup((char*)id.privkey, id.privkey_len);
        printf("PrivateKey=%s\n", privkey_str);
        free(privkey_str);
    }

    printf("Counter=%" PRIu64 "\n", id.counter);
    printf("SecurityLevel=%u\n", get_security_level(&id));

    free_identity(&id);
    return 0;
}
