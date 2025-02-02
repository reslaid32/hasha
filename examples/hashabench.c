#include "../include/hasha/all.h"
#include "../include/hasha/bits.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>

#if !defined(CLOCK_MONOTONIC)
#define CLOCK_MONOTONIC 1
#endif // CLOCK_MONOTONIC

#define BENCHMARK(ITERATIONS, HASHNAME, FUNC, ...) do {                \
    struct timespec start, end;                                         \
    clock_gettime(CLOCK_MONOTONIC, &start);                             \
    for (int i = 0; i < (ITERATIONS); ++i) {                            \
        FUNC(__VA_ARGS__);                                              \
    }                                                                   \
    clock_gettime(CLOCK_MONOTONIC, &end);                               \
    long long start_us = start.tv_sec * 1000000LL + start.tv_nsec / 1000; \
    long long end_us   = end.tv_sec * 1000000LL + end.tv_nsec / 1000;     \
    long long time_taken_us = end_us - start_us;                          \
    double time_taken_s = (double)time_taken_us / 1000000.0;              \
    double avg_time_per_iteration = (double)time_taken_us / (ITERATIONS);   \
    printf("%s: Total time: %lld us (%lf s), Avg per iteration: %.2f us\n", \
           HASHNAME, time_taken_us, time_taken_s, avg_time_per_iteration); \
} while (0)

// Function to display help/usage information
HASHA_PRIVATE_FUNC void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nSupported algorithms:\n");
    printf("  crc32, md5, sha1, sha224, sha256, sha384, sha512, sha512_224, sha512_256,\n");
    printf("  sha3_224, sha3_256, sha3_384, sha3_512, keccak224, keccak256, keccak384, keccak512\n");
    printf("  blake3_<digestlen>\n");
    printf("Options:\n");
    printf("  -t, --iters NUM     Number of iterations for benchmarking (default: 1000000)\n");
    printf("  -i, --input STRING   Input string to hash (default: 'hello')\n");
    printf("  -a, --algos STRING   Space- (or comma-) separated list of algorithms to benchmark (default: all)\n");
    printf("  -h, --help           Show this help message\n");
}

// Helper: trim leading and trailing whitespace
HASHA_PRIVATE_FUNC char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0)
        return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

int main(int argc, char *argv[]) {
    int iterations = 1000000;         // Default iterations
    const char *input = "hello";        // Default input string
    const char *algos = "all";          // Default: run all algorithms

    static struct option long_options[] = {
        {"iters", required_argument, 0, 't'},
        {"input", required_argument, 0, 'i'},
        {"algos", required_argument, 0, 'a'},
        {"help",  no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:i:a:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't':
                iterations = atoi(optarg);
                if (iterations <= 0) {
                    fprintf(stderr, "Invalid number of iterations: %s\n", optarg);
                    return 1;
                }
                break;
            case 'i':
                input = optarg;
                break;
            case 'a':
                algos = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }
    
    size_t input_len = strlen(input);
    printf("Running benchmarks with input: '%s' (%zu bytes), iterations: %d\n", input, input_len, iterations);
    printf("Selected algorithms: %s\n\n", algos);
    
    uint8_t output[512];
    
    // If "all" was passed, run a fixed set of benchmarks
    if (strcmp(algos, "all") == 0) {
        BENCHMARK(iterations, "CRC32", crc32, (const uint8_t*)input, input_len);
        BENCHMARK(iterations, "MD5", md5, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA1", sha1, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA224", sha2_224, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA256", sha2_256, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA384", sha2_384, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA512", sha2_512, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA512/224", sha2_512_224, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA512/256", sha2_512_256, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-224", sha3_224, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-256", sha3_256, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-384", sha3_384, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-512", sha3_512, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-224", keccak_224, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-256", keccak_256, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-384", keccak_384, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-512", keccak_512, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "BLAKE3-224", blake3, (const uint8_t*)input, input_len, output, 28);
        BENCHMARK(iterations, "BLAKE3-256", blake3, (const uint8_t*)input, input_len, output, 32);
        BENCHMARK(iterations, "BLAKE3-384", blake3, (const uint8_t*)input, input_len, output, 48);
        BENCHMARK(iterations, "BLAKE3-512", blake3, (const uint8_t*)input, input_len, output, 64);
    }
    else {
        // Tokenize the provided algorithm string (using both space and comma as delimiters)
        char *algos_copy = strdup(algos);
        char *token = strtok(algos_copy, " ,");
        while (token) {
            token = trim(token);
            if (strcmp(token, "crc32") == 0) {
                BENCHMARK(iterations, "CRC32", crc32, (const uint8_t*)input, input_len);
            }
            else if (strcmp(token, "md5") == 0) {
                BENCHMARK(iterations, "MD5", md5, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha1") == 0) {
                BENCHMARK(iterations, "SHA1", sha1, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha224") == 0) {
                BENCHMARK(iterations, "SHA224", sha2_224, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha256") == 0) {
                BENCHMARK(iterations, "SHA256", sha2_256, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha384") == 0) {
                BENCHMARK(iterations, "SHA384", sha2_384, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha512") == 0) {
                BENCHMARK(iterations, "SHA512", sha2_512, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha512_224") == 0) {
                BENCHMARK(iterations, "SHA512/224", sha2_512_224, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha512_256") == 0) {
                BENCHMARK(iterations, "SHA512/256", sha2_512_256, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_224") == 0) {
                BENCHMARK(iterations, "SHA3-224", sha3_224, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_256") == 0) {
                BENCHMARK(iterations, "SHA3-256", sha3_256, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_384") == 0) {
                BENCHMARK(iterations, "SHA3-384", sha3_384, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_512") == 0) {
                BENCHMARK(iterations, "SHA3-512", sha3_512, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak224") == 0) {
                BENCHMARK(iterations, "KECCAK-224", keccak_224, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak256") == 0) {
                BENCHMARK(iterations, "KECCAK-256", keccak_256, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak384") == 0) {
                BENCHMARK(iterations, "KECCAK-384", keccak_384, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak512") == 0) {
                BENCHMARK(iterations, "KECCAK-512", keccak_512, (const uint8_t*)input, input_len, output);
            }
            else if (strncmp(token, "blake3_", 7) == 0) {
                char *endptr;
                long digest_bits = strtol(token + 7, &endptr, 10);
                if ((token + 7) == endptr || digest_bits <= 0) {
                    fprintf(stderr, "Invalid BLAKE3 digest length in token '%s'\n", token);
                } else {
                    size_t digest_bytes = HASHA_bB(digest_bits);
                    char benchname[32];
                    snprintf(benchname, sizeof(benchname), "BLAKE3-%ld", digest_bits);
                    BENCHMARK(iterations, benchname, blake3, (const uint8_t*)input, input_len, output, digest_bytes);
                }
            }
            else {
                fprintf(stderr, "Unsupported algorithm: %s\n", token);
            }
            token = strtok(NULL, " ,");
        }
        free(algos_copy);
    }
    
    printf("\nBenchmark Complete!\n");
    return 0;
}
