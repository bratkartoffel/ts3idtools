#include "globals.h"
#include "sha1.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <threads.h>
#include <unistd.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

typedef struct worker_settings_t {
    thrd_t thread_id;
    uint8_t worker_id;
    uint8_t level;
    uint8_t pubkey_len;
    uint8_t one_shot;
    uint32_t block_size;
    ts3_pubkey_t pubkey[PUBKEY_LEN_B64];
} worker_settings;

typedef struct stats_settings_t {
    uint16_t interval;
    uint8_t pubkey_len;
} stats_settings;

atomic_uint_fast64_t counter = 0;
volatile bool do_stop = false;
uint64_t results[SHA_DIGEST_LENGTH * 8 + 1];

int stats_loop(void *arg) {
    debug_printf("> stats_loop(%p)\n", arg);
    stats_settings *settings = arg;
    // immediately stop stats thread if disabled
    if (settings->interval == 0) {
        debug_printf("< stats_loop(): %p\n", NULL);
        return 0;
    }

    uint64_t old_counter = counter;
    while (!do_stop) {
        sleep(settings->interval);
        uint64_t new_counter = counter;

        uint64_t diff_counter = new_counter - old_counter;
        long double mh_diff_counter = (long double) diff_counter / 1000000;
        long double mh_performance = mh_diff_counter / settings->interval;

        bool found = false;
        for (int i = SHA_DIGEST_LENGTH * 8 - 1; i >= 0; i--) {
            if (results[i] != 0) {
                printf("%.02Lf mh/s - counter currently at %" PRIu64 " (best result: level %u with counter %" PRIu64 ")\n",
                       mh_performance, new_counter, i, results[i]);
                fflush(stdout);
                found = true;
                break;
            }
        }
        if (!found) {
            printf("%.02Lf mh/s - counter currently at %" PRIu64 " (best result: {none})\n",
                   mh_performance, new_counter);
            fflush(stdout);
        }
        old_counter = new_counter;
        fflush(stdout);
    }
    debug_printf("< stats_loop(): %p\n", NULL);
    return 0;
}

int worker_loop(void *arg) {
    debug_printf("> worker_loop(%p)\n", arg);
    uint32_t first_block_state[5];
    uint32_t hash[5];
    worker_settings *settings = arg;
    do_sha1_first_block(settings->pubkey, first_block_state);
    // no logging after this point, performance sensitive!
    while (!do_stop) {
        uint64_t upper = counter += settings->block_size;
        uint64_t lower = upper - settings->block_size;
        size_t data_len = append_counter(settings->pubkey, settings->pubkey_len, lower);

        if (data_len > MAX_MSG_LENGTH_2_BLOCKS) {
            fprintf(stdout, "You've reached the end the calculating abilities of this tool.\n");
            fprintf(stdout, "Continuing here makes no sense as the hashrate would half.\n");
            fprintf(stdout, "Abort computing process...\n");
            do_stop = true;
            if (settings->one_shot) {
                do_stop = true;
                return 0;
            }
        }
        for (uint64_t i = lower; i < upper; i++) {
            do_sha1_second_block_with_cpu_ext(settings->pubkey, data_len, first_block_state, hash);
            const uint8_t calc_level = leading_zero_bits(hash);
            if (calc_level >= settings->level) {
                if (results[calc_level] == 0) {
                    printf("Thread[%u]: Found level=%u with counter %" PRIu64 "!\n",
                           settings->worker_id, calc_level, i);
                    fflush(stdout);
                    results[calc_level] = i;
                }
                if (settings->one_shot) {
                    do_stop = true;
                    return 0;
                }
            }
            data_len = increment_counter(settings->pubkey, settings->pubkey_len, data_len);
        }
    }
    debug_printf("< worker_loop(): %p\n", NULL);
    return 0;
}

void sigHandler(int signal) {
    debug_printf("> sigHandler(%i)\n", signal);
    do_stop = true;
    debug_printf("< sigHandler\n");
}

void print_usage(const char *appName) {
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -b, --blocksize=NUMBER       Blocksize for the worker threads\n"
           "                               Power to 2, defaults to 21 (= 2,097,152)\n"
           "  -c, --counter=NUMBER         Starting value for counter\n"
           "  -h, --help                   Print this usage information\n"
           "  -p, --publickey=STRING       Public key of identity (usually starts with 'MEw')\n"
           "  -l, --level=NUMBER           Minimum security level to print out\n"
           "                               Should not be too small, defaults to 24\n"
           #ifdef HAVE_SYS_RESOURCE_H
           "  -n, --nice=NUMBER            Priority of process (nice value)\n"
           "                               Between -20 and 19, defaults to 10\n"
           #endif
           "  -o, --one-shot               Stop when the given level was found\n"
           "  -s, --stats-interval=NUMBER  Interval (in seconds) to print statistics\n"
           "                               When not set, no statistics are printed\n"
           "  -t, --threads=NUMBER         Count of parallel worker threads to spawn\n"
           "                               Should be lesser than the number of cores, defaults to 2\n"
           "  -v, --verbose                Enable debug output\n"
           "\n"
           "ts3idtools - v%s - created by bratkartoffel - Code at https://github.com/bratkartoffel/ts3idtools\n"
           "\n", appName, VERSION);
}

bool validate_arguments(ts3_pubkey_t *pubkey, uint8_t threads, uint8_t level, uint8_t blockSize,
                               uint16_t statsInterval, int nice, bool one_shot) {
    debug_printf("> validate_arguments(%s, %u, %u, %u, %u, %i, %u)\n",
                 (const char*) pubkey, threads, level, blockSize, statsInterval, nice, one_shot);
    bool result = true;
    if (!pubkey) {
        fprintf(stderr, "Missing required argument: 'public key'\n");
        result = false;
    } else {
        if (strncmp((const char*) pubkey, "ME", 2) != 0) {
            fprintf(stderr, "Invalid argument: 'public key' has wrong format\n");
            result = false;
        }
        if (strlen((const char*) pubkey) > PUBKEY_LEN_B64) {
            fprintf(stderr, "Invalid argument: 'public key' is too long\n");
            result = false;
        }
    }
    if (threads == 0 || threads >= 128) {
        fprintf(stderr, "Invalid argument: 'threads' must be between 1 and 128\n");
        result = false;
    }
    if (level < 16 || level >= 128) {
        fprintf(stderr, "Invalid argument: 'level' must be between 16 and 128\n");
        result = false;
    }
    if (blockSize < 19 || blockSize > 26) {
        fprintf(stderr, "Invalid argument: 'blockSize' must be between 19 and 26\n");
        result = false;
    }
    if (nice < -20 || nice > 19) {
        fprintf(stderr, "Invalid argument: 'nice' must be between -20 and 19\n");
        result = false;
    }

    ((void) statsInterval); // no check needed
    ((void) one_shot); // no check needed

    debug_printf("< validate_arguments(): %u\n", result);
    return result;
}

bool set_nice(int nice) {
    debug_printf("> set_nice(%i)\n", nice);
    bool result = true;
#ifdef HAVE_SYS_RESOURCE_H
    const id_t pid = getpid();
    if (setpriority(PRIO_PROCESS, pid, nice) != 0) {
        fprintf(stderr, "setpriority failed: %u: %s\n", errno, strerror(errno));
        result = false;
    }
#endif
    debug_printf("< set_nice(): %u\n", result);
    return result;
}

bool start_workers(uint8_t threads, worker_settings settings[threads],
                          const ts3_pubkey_t *pubkey, uint8_t blockSize, uint8_t level, bool one_shot) {
    debug_printf("> start_workers(%u, %p, %s, %u, %u, %u)\n",
                 threads, (void *) settings, (const char*) pubkey, blockSize, level, one_shot);
    bool result = true;
    for (uint8_t i = 0; i < threads; i++) {
        settings[i].worker_id = i;
        settings[i].one_shot = one_shot;
        settings[i].level = level;
        settings[i].block_size = 1 << blockSize;
        settings[i].pubkey_len = strlen((const char*) pubkey);
        memcpy(settings[i].pubkey, pubkey, settings[i].pubkey_len);

        debug_printf("> start_workers(): starting %u\n", i);
        if (thrd_create(&settings[i].thread_id, worker_loop, &settings[i])) {
            fprintf(stderr, "thrd_create(worker_loop[%u]) failed\n", i);
            result = false;
            break;
        }
    }
    debug_printf("< start_workers(): %u\n", result);
    return result;
}

void print_arguments(const ts3_pubkey_t *pubkey, uint8_t threads, uint8_t level, uint8_t blockSize,
                            uint16_t statsInterval, int nice, bool one_shot) {
    debug_printf("> print_arguments(%s, %u, %u, %u, %u, %i, %u)\n",
                 (const char*) pubkey, threads, level, blockSize, statsInterval, nice, one_shot);
    ((void) nice);
    debug_printf("  print_arguments: blockSize=%u\n", blockSize);
    debug_printf("  print_arguments: counter=%" PRIu64 "\n", counter);
    debug_printf("  print_arguments: pubkey=%s\n", (const char*) pubkey);
    debug_printf("  print_arguments: oneShot=%u\n", one_shot);
    debug_printf("  print_arguments: level=%u\n", level);
    debug_printf("  print_arguments: statsInterval=%u\n", statsInterval);
    debug_printf("  print_arguments: threads=%u\n", threads);
#ifdef HAVE_SYS_RESOURCE_H
    debug_printf("  print_arguments: nice=%i\n", nice);
#endif
    debug_printf("< print_arguments()\n");
}

uint64_t current_time_millis() {
    struct timeval time;
    gettimeofday(&time, NULL);
    const uint64_t s1 = (uint64_t) (time.tv_sec) * 1000;
    const uint64_t s2 = (time.tv_usec / 1000);
    return s1 + s2;
}

void print_final_statistics(const uint64_t start_time, const uint8_t threads, const uint64_t start_counter) {
    const uint64_t end_time = current_time_millis();
    uint64_t end_counter = counter;
    uint64_t diff_time = end_time - start_time;
    long double diff_counter = end_counter - start_counter;
    diff_counter /= 1000000;
    long double performance_total = diff_counter / diff_time * 1000;

    printf("-------------------\n");
    printf("Results:      {");
    bool found = false;
    for (int i = 0; i < SHA_DIGEST_LENGTH * 8; i++) {
        if (results[i] != 0) {
            if (found) printf(", ");
            printf("%u=%" PRIu64 "", i, results[i]);
            found = true;
        }
    }
    printf("}\n");
    printf("Last counter: %" PRIu64 "\n", end_counter);
    printf("Runtime:      %.02Lf s\n", (long double) diff_time / 1000.0);
    printf("Performance:  %.02Lf mh/s\n", performance_total);
    printf("Per Thread:   %.02Lf mh/s\n", performance_total / threads);
    fflush(stdout);
}

void join_workers(uint8_t threads, const worker_settings *settings) {
    debug_printf("> join_workers(%u, %p)\n", threads, (void *) settings);
    for (uint8_t i = 0; i < threads; i++) {
        int res;
        if (thrd_join(settings[i].thread_id, &res)) {
            fprintf(stderr, "thrd_join(%u) failed\n", i);
        }
    }
    debug_printf("< join_workers()\n");
}

int main(int argc, char** argv) {
    const uint64_t start_time = current_time_millis();
    ts3_pubkey_t *pubkey = NULL;
    uint8_t threads = 2;
    uint8_t level = 24;
    uint8_t blockSize = 21;
    uint16_t statsInterval = 0;
    int nice = 10;
    bool one_shot = false;
    uint64_t start_counter = 0;

#ifdef HAVE_SYS_RESOURCE_H
    const char *options = "b:c:hl:n:op:s:t:vV";
    static struct option long_options[] = {
            {"blocksize",      optional_argument, NULL, 'b'},
            {"counter",        optional_argument, NULL, 'c'},
            {"help",           no_argument,       NULL, 'h'},
            {"publickey",      required_argument, NULL, 'p'},
            {"level",          optional_argument, NULL, 'l'},
            {"nice",           optional_argument, NULL, 'n'},
            {"one-shot",       no_argument,       NULL, 'o'},
            {"stats-interval", optional_argument, NULL, 's'},
            {"threads",        optional_argument, NULL, 't'},
            {"verbose",        no_argument,       NULL, 'v'},
            {"version",        no_argument,       NULL, 'V'},
            {NULL,          0,                 NULL, 0}
    };
#else
    const char *options = "b:c:hl:op:s:t:vV";
    static struct option long_options[] = {
            {"blocksize",      required_argument, NULL, 'b'},
            {"counter",        required_argument, NULL, 'c'},
            {"help",           no_argument,       NULL, 'h'},
            {"publickey",      required_argument, NULL, 'p'},
            {"level",          required_argument, NULL, 'l'},
            {"one-shot",       no_argument,       NULL, 'o'},
            {"stats-interval", required_argument, NULL, 's'},
            {"threads",        required_argument, NULL, 't'},
            {"verbose",        no_argument,       NULL, 'v'},
            {"version",        no_argument,       NULL, 'V'},
            {NULL,          0,                 NULL, 0}
    };
#endif
    bool missing_value = false;
    int c;
    while ((c = getopt_long(argc, argv, options, long_options, NULL)) != -1) {
        switch (c) {
            case 'b':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                blockSize = strtol(optarg, NULL, 10);
                break;
            case 'c':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                start_counter = strtoll(optarg, NULL, 10);
                counter = start_counter;
                break;
            case 'h':
                print_usage(*argv);
                return 0;
            case 'l':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                level = strtol(optarg, NULL, 10);
                break;
#ifdef HAVE_SYS_RESOURCE_H
                case 'n':
                    nice = (int) strtol(optarg, NULL, 10);
                    break;
#endif
            case 'o':
                one_shot = true;
                break;
            case 'p':
                pubkey = (ts3_pubkey_t*) optarg;
                break;
            case 's':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                statsInterval = strtol(optarg, NULL, 10);
                break;
            case 't':
                if (!optarg) {
                    fprintf(stderr, "Value missing for option '%c'\n", c);
                    missing_value = true;
                    continue;
                }
                threads = strtol(optarg, NULL, 10);
                break;
            case 'v':
                debug = true;
                break;
            case 'V':
                printf("ts3idcrunch version %s\n", VERSION);
                return 0;
            default:
                fprintf(stderr, "Unknown option given: '%c'\n", optopt);
                break;
        }
    }

    if (missing_value) {
        print_usage(*argv);
        return 1;
    }

    if (!validate_arguments(pubkey, threads, level, blockSize, statsInterval, nice, one_shot)) {
        fprintf(stderr, "validate_arguments() failed\n");
        print_usage(*argv);
        return 1;
    }

    print_arguments(pubkey, threads, level, blockSize, statsInterval, nice, one_shot);

    if (!set_nice(nice)) {
        fprintf(stderr, "set_nice() failed\n");
        return 1;
    }

    worker_settings settings[threads];
    if (!start_workers(threads, settings, pubkey, blockSize, level, one_shot)) {
        fprintf(stderr, "start_workers() failed\n");
        return 1;
    }

    thrd_t stats_thread;
    stats_settings stats_cfg;
    stats_cfg.interval = statsInterval;
    stats_cfg.pubkey_len = settings[0].pubkey_len;
    if (thrd_create(&stats_thread, stats_loop, &stats_cfg)) {
        fprintf(stderr, "thrd_create(stats_loop) failed\n");
        return 1;
    }

    printf("Press CTRL + C to cancel generation...\n");
    fflush(stdout);
    if (signal(SIGINT, sigHandler) == SIG_ERR || signal(SIGTERM, sigHandler) == SIG_ERR) {
        fprintf(stderr, "Could not setup signal handler!\n");
        return 1;
    }

    // join all workers
    join_workers(threads, settings);
    print_final_statistics(start_time, threads, start_counter);

    return 0;
}
