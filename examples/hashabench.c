#include "../include/hasha/all.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>

#define BENCHMARK(ITERATIONS, HASHNAME, FUNC, ...) do {                \
    struct timespec start, end;                                         \
    clock_gettime(CLOCK_MONOTONIC, &start);                             \
    for (int i = 0; i < (ITERATIONS); ++i) {                            \
        FUNC(__VA_ARGS__);                                              \
    }                                                                   \
    clock_gettime(CLOCK_MONOTONIC, &end);                               \
    long long start_us = start.tv_sec * 1000000LL + start.tv_nsec / 1000; \
    long long end_us = end.tv_sec * 1000000LL + end.tv_nsec / 1000;     \
    long long time_taken_us = end_us - start_us;                        \
    double time_taken_s = (double)time_taken_us / 1000000.0;            \
    double avg_time_per_iteration = (double)time_taken_us / (ITERATIONS); \
    printf("%s: Total time: %lld us (%lf s), Avg per iteration: %.2f us\n", \
           HASHNAME, time_taken_us, time_taken_s, avg_time_per_iteration); \
} while (0)

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -t, --iters NUM     Number of iterations for benchmarking (default: 1000)\n");
    printf("  -i, --input STRING   Input string to hash (default: 'hello')\n");
    printf("  -h, --help           Show this help message\n");
}

#if !defined(CLOCK_MONOTONIC)
#define CLOCK_MONOTONIC 1
#endif // CLOCK_MONOTONIC

int main(int argc, char *argv[]) {
    int iterations = 1000;  // Default number of iterations
    const char *input = "hello"; // Default input string

    static struct option long_options[] = {
        {"iters", required_argument, 0, 't'},
        {"input", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:i:h", long_options, &option_index)) != -1) {
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
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    size_t input_len = strlen(input);

    printf("Running benchmarks with input: '%s' (%zu bytes), iterations: %d\n\n", input, input_len, iterations);

    uint8_t output[512];

    // CRC32
    BENCHMARK(iterations, "CRC32", crc32, (const uint8_t*)input, input_len);

    // MD5
    BENCHMARK(iterations, "MD5", md5, (const uint8_t*)input, input_len, output);

    // SHA1
    BENCHMARK(iterations, "SHA1", sha1, (const uint8_t*)input, input_len, output);

    // SHA2
    BENCHMARK(iterations, "SHA2-224", sha2_224, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA2-256", sha2_256, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA2-384", sha2_384, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA2-512", sha2_512, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA2-512/224", sha2_512_224, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA2-512/256", sha2_512_256, (const uint8_t*)input, input_len, output);

    // SHA3
    BENCHMARK(iterations, "SHA3-224", sha3_224, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA3-256", sha3_256, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA3-384", sha3_384, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "SHA3-512", sha3_512, (const uint8_t*)input, input_len, output);

    // KECCAK
    BENCHMARK(iterations, "KECCAK-224", keccak_224, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-256", keccak_256, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-384", keccak_384, (const uint8_t*)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-512", keccak_512, (const uint8_t*)input, input_len, output);

    // BLAKE3
    BENCHMARK(iterations, "BLAKE3-224", blake3, (const uint8_t*)input, input_len, output, 28);
    BENCHMARK(iterations, "BLAKE3-256", blake3, (const uint8_t*)input, input_len, output, 32);
    BENCHMARK(iterations, "BLAKE3-384", blake3, (const uint8_t*)input, input_len, output, 48);
    BENCHMARK(iterations, "BLAKE3-512", blake3, (const uint8_t*)input, input_len, output, 64);

    printf("\nBenchmark Complete!\n");
    return 0;
}
