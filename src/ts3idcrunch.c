#include "globals.h"
#include "sha1.h"

#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <errno.h>
#include <sys/resource.h>
#endif

typedef struct worker_settings_t {
    pthread_t thread_id;
    uint8_t worker_id;
    uint8_t level;
    uint8_t pubkey_len;
    uint8_t one_shot;
    uint32_t block_size;
    uint8_t pubkey[PUBKEY_LEN_B64];
} worker_settings;

static atomic_uint_fast64_t counter = 0;
static volatile bool do_stop = false;
static uint64_t results[SHA_DIGEST_LENGTH * 8 + 1];
static pthread_mutex_t keypress_lock;

static void *stats_start(void *arg) {
    debug_printf("> stats_start(%p)\n", arg);
    uint16_t statsInterval = *(uint16_t *) arg;
    // immediately stop stats thread if disabled
    if (statsInterval == 0) return NULL;

    uint64_t old_counter = counter;
    while (!do_stop) {
        sleep(statsInterval);
        uint64_t new_counter = counter;

        long double diff_counter = new_counter - old_counter;
        diff_counter /= 1000000;
        long double performance_total = diff_counter / statsInterval;
        printf("%.02Lf mh/s - counter currently at %" PRIu64 " (best result: ", performance_total, new_counter);

        bool found = false;
        for (int i = SHA_DIGEST_LENGTH * 8 - 1; i >= 0; i--) {
            if (results[i] != 0) {
                printf("level %u with counter %" PRIu64 ")\n", i, results[i]);
                found = true;
                break;
            }
        }
        if (!found) {
            printf("{none})\n");
        }
        old_counter = new_counter;
        fflush(stdout);
    }
    debug_printf("< stats_start(): %p\n", NULL);
    return NULL;
}

static void *worker_start_software(void *arg) {
    debug_printf("> worker_start_software(%p)\n", arg);
    worker_settings *settings = arg;
    uint32_t first_block_state[5]  __attribute__((aligned (16)));
    do_sha1_first_block(settings->pubkey, first_block_state);
    size_t pubkey_len = settings->pubkey_len;
    uint8_t hash[SHA_DIGEST_LENGTH];
    uint8_t level_bits_short_circuit =
            settings->level % 8 == 0 ? settings->level : settings->level - (settings->level % 8);
    debug_printf("  worker_start_software: level_bits_short_circuit=%u\n", level_bits_short_circuit);
    // no logging after this point, performance sensitive!
    while (!do_stop) {
        uint64_t value = atomic_fetch_add(&counter, settings->block_size);
        uint64_t bounds = value + settings->block_size;
        for (uint64_t i = value; i < bounds; i++) {
            size_t data_len = append_counter(settings->pubkey, pubkey_len, i);
            do_sha1_second_block_software(settings->pubkey, data_len, first_block_state, hash);
            uint8_t calc_level = leading_zero_bits(hash, level_bits_short_circuit);
            if (calc_level >= settings->level) {
                if (results[calc_level] == 0) {
                    printf("Thread[%u]: Found level=%u with counter %" PRIu64 "!\n", settings->worker_id, calc_level,
                           i);
                    results[calc_level] = i;
                }
                fflush(stdout);
                if (settings->one_shot) {
                    pthread_mutex_unlock(&keypress_lock);
                    break;
                }
            }
        }
    }
    debug_printf("< worker_start_software(): %p\n", NULL);
    return NULL;
}

static void *worker_start_cpu(void *arg) {
    debug_printf("> worker_start_cpu(%p)\n", arg);
    worker_settings *settings = arg;
    uint32_t first_block_state[5]  __attribute__((aligned (16)));
    do_sha1_first_block(settings->pubkey, first_block_state);
    size_t pubkey_len = settings->pubkey_len;
    uint8_t hash[SHA_DIGEST_LENGTH];
    uint8_t level_bits_short_circuit =
            settings->level % 8 == 0 ? settings->level : settings->level - (settings->level % 8);
    debug_printf("  worker_start_cpu: level_bits_short_circuit=%u\n", level_bits_short_circuit);
    // no logging after this point, performance sensitive!
    while (!do_stop) {
        uint64_t value = atomic_fetch_add(&counter, settings->block_size);
        uint64_t bounds = value + settings->block_size;
        for (uint64_t i = value; i < bounds; i++) {
            size_t data_len = append_counter(settings->pubkey, pubkey_len, i);
            do_sha1_second_block_cpu(settings->pubkey, data_len, first_block_state, hash);
            uint8_t calc_level = leading_zero_bits(hash, level_bits_short_circuit);
            if (calc_level >= settings->level) {
                if (results[calc_level] == 0) {
                    printf("Thread[%u]: Found level=%u with counter %" PRIu64 "!\n", settings->worker_id, calc_level,
                           i);
                    results[calc_level] = i;
                }
                fflush(stdout);
                if (settings->one_shot) {
                    pthread_mutex_unlock(&keypress_lock);
                    break;
                }
            }
        }
    }
    debug_printf("< worker_start_cpu(): %p\n", NULL);
    return NULL;
}

static void sigHandler(int signal) {
    debug_printf("> sigHandler(%i)\n", signal);
    do_stop = true;
    debug_printf("< sigHandler\n");
}

static void print_usage(const char *appName) {
    printf("Usage: %s [options]\n"
           "Options:\n"
           "  -b, --blocksize=NUMBER       Blocksize for the worker threads\n"
           "                               Power to 2, defaults to 20 (= 1,048,576)\n"
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

static bool validate_arguments(const char *pubkey, uint8_t threads, uint8_t level, uint8_t blockSize,
                               uint16_t statsInterval, int nice, bool one_shot) {
    debug_printf("> validate_arguments(%s, %u, %u, %u, %u, %i, %u)\n",
                 pubkey, threads, level, blockSize, statsInterval, nice, one_shot);
    bool result = true;
    if (!pubkey) {
        fprintf(stderr, "Missing required argument: 'public key'\n");
        result = false;
    } else {
        if (strncmp(pubkey, "ME", 2) != 0) {
            fprintf(stderr, "Invalid argument: 'public key' has wrong format\n");
            result = false;
        }
        if (strlen(pubkey) > 512) {
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
    if (blockSize < 18 || blockSize > 24) {
        fprintf(stderr, "Invalid argument: 'blockSize' must be between 18 and 24\n");
        result = false;
    }
    if (nice > 19 || nice < -20) {
        fprintf(stderr, "Invalid argument: 'nice' must be between -20 and 19\n");
        result = false;
    }

    ((void) statsInterval); // no check needed
    ((void) one_shot); // no check needed

    debug_printf("< validate_arguments(): %u\n", result);
    return result;
}

static bool set_nice(int nice) {
    debug_printf("> set_nice(%i)\n", nice);
    bool result = true;
#ifdef HAVE_SYS_RESOURCE_H
    id_t pid = getpid();
    if (setpriority(PRIO_PROCESS, pid, nice) != 0) {
        fprintf(stderr, "setpriority failed: %u: %s\n", errno, strerror(errno));
        result = false;
    }
#endif
    debug_printf("< set_nice(): %u\n", result);
    return result;
}

static bool start_workers(uint8_t threads, worker_settings settings[threads],
                          const char *pubkey, uint8_t blockSize, uint8_t level, bool one_shot) {
    debug_printf("> start_workers(%u, %p, %s, %u, %u, %u)\n",
                 threads, (void *) settings, pubkey, blockSize, level, one_shot);
    bool result = true;
    for (uint8_t i = 0; i < threads; i++) {
        memset(&settings[i], 0x00, sizeof(struct worker_settings_t));
        settings[i].thread_id = 0;
        settings[i].worker_id = i;
        settings[i].one_shot = one_shot;
        settings[i].level = level;
        settings[i].block_size = 1 << blockSize;
        settings[i].pubkey_len = strlen(pubkey);
        memcpy(settings[i].pubkey, pubkey, settings[i].pubkey_len);

        void *(*worker_func)(void *);
        if (i == 0 && check_for_intel_sha_extensions()) {
            worker_func = worker_start_cpu;
        } else {
            worker_func = worker_start_software;
        }
        debug_printf("> start_workers(): starting %u\n", i);
        if (pthread_create(&settings[i].thread_id, NULL, worker_func, &settings[i])) {
            fprintf(stderr, "pthread_create(%u) failed\n", i);
            result = false;
            break;
        }
    }
    debug_printf("< start_workers(): %u\n", result);
    return result;
}

static void wait_for_stop(bool one_shot) {
    debug_printf("> wait_for_stop(%u)\n", one_shot);
    if (one_shot) {
        printf("Start crunching...\n");
        fflush(stdout);
        pthread_mutex_lock(&keypress_lock);   // lock the mutex
        pthread_mutex_lock(&keypress_lock);   // wait until it's unlocked again (key pressed)
        pthread_mutex_unlock(&keypress_lock); // unlock, we'd like to stop
    } else {
        printf("Press CTRL + C to cancel generation...\n");
        fflush(stdout);
        if (signal(SIGINT, sigHandler) == SIG_ERR || signal(SIGTERM, sigHandler) == SIG_ERR) {
            fprintf(stderr, "Could not setup signal handler, falling back to reading from STDIN\n");
            getchar();
        } else {
            while (!do_stop) {
                sleep(1);
            }
        }
    }
    debug_printf("< wait_for_stop()\n");
}

static void print_arguments(const char *pubkey, uint8_t threads, uint8_t level, uint8_t blockSize,
                            uint16_t statsInterval, int nice, bool one_shot) {
    debug_printf("> print_arguments(%s, %u, %u, %u, %u, %i, %u)\n",
                 pubkey, threads, level, blockSize, statsInterval, nice, one_shot);
    ((void) nice);
    debug_printf("  print_arguments: blockSize=%u\n", blockSize);
    debug_printf("  print_arguments: counter=%" PRIu64 "\n", counter);
    debug_printf("  print_arguments: pubkey=%s\n", pubkey);
    debug_printf("  print_arguments: oneShot=%u\n", one_shot);
    debug_printf("  print_arguments: level=%u\n", level);
    debug_printf("  print_arguments: statsInterval=%u\n", statsInterval);
    debug_printf("  print_arguments: threads=%u\n", threads);
#ifdef HAVE_SYS_RESOURCE_H
    debug_printf("  print_arguments: nice=%i\n", nice);
#endif
    debug_printf("< print_arguments()\n");
}

static uint64_t current_time_millis() {
    struct timeval time;
    gettimeofday(&time, NULL);
    uint64_t s1 = (uint64_t) (time.tv_sec) * 1000;
    uint64_t s2 = (time.tv_usec / 1000);
    return s1 + s2;
}

static void print_final_statistics(const uint64_t start_time, const uint8_t threads, const uint64_t start_counter) {
    uint64_t end_time = current_time_millis();
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
    printf("Runtime:      %.02f s\n", diff_time / 1000.0);
    printf("Performance:  %.02Lf mh/s\n", performance_total);
    printf("Per Thread:   %.02Lf mh/s\n", performance_total / threads);
    fflush(stdout);
}

static void join_workers(uint8_t threads, const worker_settings *settings) {
    debug_printf("> join_workers(%u, %p)\n", threads, (void *) settings);
    for (uint8_t i = 0; i < threads; i++) {
        void *res;
        if (pthread_join(settings[i].thread_id, &res)) {
            fprintf(stderr, "pthread_join(%u) failed\n", i);
        }
    }
    debug_printf("< join_workers()\n");
}

int main(int argc, char **argv) {
    const uint64_t start_time = current_time_millis();
    const char *pubkey = NULL;
    uint8_t threads = 2;
    uint8_t level = 24;
    uint8_t blockSize = 20;
    uint16_t statsInterval = 0;
    int nice = 10;
    bool one_shot = false;
    uint64_t start_counter = 0;

#ifdef HAVE_SYS_RESOURCE_H
    const char *options = "b:c:hl:n:op:s:t:v";
    static struct option long_options[] = {
            {"blocksize",      optional_argument, 0, 'b'},
            {"counter",        optional_argument, 0, 'c'},
            {"help",           no_argument,       0, 'h'},
            {"publickey",      required_argument, 0, 'p'},
            {"level",          optional_argument, 0, 'l'},
            {"nice",           optional_argument, 0, 'n'},
            {"one-shot",       no_argument,       0, 'o'},
            {"stats-interval", optional_argument, 0, 's'},
            {"threads",        optional_argument, 0, 't'},
            {"verbose",        no_argument,       0, 'v'},
            {0,                0,                 0, 0}
    };
#else
    const char *options = "b:c:hl:op:s:t:v";
    static struct option long_options[] = {
            {"blocksize",      required_argument, 0, 'b'},
            {"counter",        required_argument, 0, 'c'},
            {"help",           no_argument,       0, 'h'},
            {"publickey",      required_argument, 0, 'p'},
            {"level",          required_argument, 0, 'l'},
            {"one-shot",       no_argument,       0, 'o'},
            {"stats-interval", required_argument, 0, 's'},
            {"threads",        required_argument, 0, 't'},
            {"verbose",        no_argument,       0, 'v'},
            {0,                0,                 0, 0}
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
                    nice = strtol(optarg, NULL, 10);
                    break;
#endif
            case 'o':
                one_shot = true;
                break;
            case 'p':
                pubkey = optarg;
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

    pthread_t stats_thread;
    if (pthread_create(&stats_thread, NULL, &stats_start, &statsInterval)) {
        fprintf(stderr, "pthread_create(stats_thread) failed\n");
        return 1;
    }

    wait_for_stop(one_shot);
    do_stop = true;

    // join all workers
    join_workers(threads, settings);
    print_final_statistics(start_time, threads, start_counter);

    return 0;
}
