#include "../include/hasha/all.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>

// #define INCLUDE_OPENSSL

#if defined(INCLUDE_OPENSSL)
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif // INCLUDE_OPENSSL

#if !defined(CLOCK_MONOTONIC)
#define CLOCK_MONOTONIC 1
#endif // CLOCK_MONOTONIC

#define BENCHMARK(ITERATIONS, HASHNAME, FUNC, FILE_, ...) do {                \
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
    if (FILE_) {                                                           \
        fprintf(FILE_, "%s,%lld,%lf,%.2f\n", HASHNAME, time_taken_us, time_taken_s, avg_time_per_iteration); \
    } \
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

#if defined(INCLUDE_OPENSSL)
void openssl_evp_checksum(const EVP_MD *evpmd, const unsigned char *data, size_t len, unsigned char *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return;
    }

    if (EVP_DigestInit_ex(mdctx, evpmd, NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestUpdate(mdctx, data, len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
    }

    EVP_MD_CTX_free(mdctx);
}
#endif // INCLUDE_OPENSSL

int main(int argc, char *argv[]) {
    int iterations = 1000000;         // Default iterations
    const char *input = "hello";        // Default input string
    const char *algos = "all";          // Default: run all algorithms
    const char *save_file = NULL;       // Default: (null)

    static struct option long_options[] = {
        {"iters", required_argument, 0, 't'},
        {"input", required_argument, 0, 'i'},
        {"algos", required_argument, 0, 'a'},
        {"svres", required_argument, 0, 'r'},
        {"help",  no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:i:a:h:r:", long_options, &option_index)) != -1) {
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
            case 'r':
                save_file = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    FILE *result_file = NULL;
    if (save_file) {
        result_file = fopen(save_file, "w");
        if (!result_file) {
            fprintf(stderr, "Could not open file for saving results: %s\n", save_file);
            return 1;
        }
        fprintf(result_file, "Algorithm,Time (us),Total Time (s),Avg Time per Iteration (us)\n");
    }
    
    size_t input_len = strlen(input);
    printf("Running benchmarks with input: '%s' (%zu bytes), iterations: %d\n", input, input_len, iterations);
    printf("Selected algorithms: %s\n\n", algos);
    
    uint8_t output[512];
    
    // If "all" was passed, run a fixed set of benchmarks
    if (strcmp(algos, "all") == 0) {
        BENCHMARK(iterations, "CRC32", crc32, result_file, (const uint8_t*)input, input_len);
        BENCHMARK(iterations, "MD5", md5, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA1", sha1, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA224", sha2_224, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA256", sha2_256, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA384", sha2_384, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA512", sha2_512, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA512/224", sha2_512_224, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA512/256", sha2_512_256, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-224", sha3_224, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-256", sha3_256, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-384", sha3_384, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "SHA3-512", sha3_512, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-224", keccak_224, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-256", keccak_256, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-384", keccak_384, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "KECCAK-512", keccak_512, result_file, (const uint8_t*)input, input_len, output);
        BENCHMARK(iterations, "BLAKE3-224", blake3, result_file, (const uint8_t*)input, input_len, output, 28);
        BENCHMARK(iterations, "BLAKE3-256", blake3, result_file, (const uint8_t*)input, input_len, output, 32);
        BENCHMARK(iterations, "BLAKE3-384", blake3, result_file, (const uint8_t*)input, input_len, output, 48);
        BENCHMARK(iterations, "BLAKE3-512", blake3, result_file, (const uint8_t*)input, input_len, output, 64);
    }
    else {
        // Tokenize the provided algorithm string (using both space and comma as delimiters)
        char *algos_copy = strdup(algos);
        char *token = strtok(algos_copy, " ,");
        while (token) {
            token = trim(token);
            if (strcmp(token, "crc32") == 0) {
                BENCHMARK(iterations, "hasha CRC32", crc32, result_file, (const uint8_t*)input, input_len);
            }
            else if (strcmp(token, "md5") == 0) {
                BENCHMARK(iterations, "hasha MD5", md5, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha1") == 0) {
                BENCHMARK(iterations, "hasha SHA1", sha1, result_file, (const uint8_t*)input, input_len, output);
            }

            else if (strcmp(token, "sha224") == 0) {
                BENCHMARK(iterations, "hasha SHA224", sha2_224, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha256") == 0) {
                BENCHMARK(iterations, "hasha SHA256", sha2_256, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha384") == 0) {
                BENCHMARK(iterations, "hasha SHA384", sha2_384, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha512") == 0) {
                BENCHMARK(iterations, "hasha SHA512", sha2_512, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha512_224") == 0) {
                BENCHMARK(iterations, "hasha SHA512/224", sha2_512_224, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha512_256") == 0) {
                BENCHMARK(iterations, "hasha SHA512/256", sha2_512_256, result_file, (const uint8_t*)input, input_len, output);
            }

            #if defined(INCLUDE_OPENSSL)
            else if (strcmp(token, "openssl-sha224") == 0) {
                BENCHMARK(iterations, "openssl SHA224", SHA224, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-sha256") == 0) {
                BENCHMARK(iterations, "openssl SHA256", SHA256, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-sha384") == 0) {
                BENCHMARK(iterations, "openssl SHA384", SHA384, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-sha512") == 0) {
                BENCHMARK(iterations, "openssl SHA512", SHA512, result_file, (const uint8_t*)input, input_len, output);
            }
            #endif // INCLUDE_OPENSSL

            #if defined(INCLUDE_OPENSSL)
            else if (strcmp(token, "openssl-evp-sha224") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA224", openssl_evp_checksum, result_file, EVP_sha224(), (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-evp-sha256") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA256", openssl_evp_checksum, result_file, EVP_sha256(), (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-evp-sha384") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA384", openssl_evp_checksum, result_file, EVP_sha384(), (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-evp-sha512") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA512", openssl_evp_checksum, result_file, EVP_sha512(), (const uint8_t*)input, input_len, output);
            }
            #endif // INCLUDE_OPENSSL

            else if (strcmp(token, "sha3_224") == 0) {
                BENCHMARK(iterations, "hasha SHA3-224", sha3_224, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_256") == 0) {
                BENCHMARK(iterations, "hasha SHA3-256", sha3_256, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_384") == 0) {
                BENCHMARK(iterations, "hasha SHA3-384", sha3_384, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "sha3_512") == 0) {
                BENCHMARK(iterations, "hasha SHA3-512", sha3_512, result_file, (const uint8_t*)input, input_len, output);
            }

            #if defined(INCLUDE_OPENSSL)
            else if (strcmp(token, "openssl-evp-sha3_224") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA3-224", openssl_evp_checksum, result_file, EVP_sha3_224(), (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-evp-sha3_256") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA3-256", openssl_evp_checksum, result_file, EVP_sha3_256(), (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-evp-sha3_384") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA3-384", openssl_evp_checksum, result_file, EVP_sha3_384(), (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "openssl-evp-sha3_512") == 0) {
                BENCHMARK(iterations, "openssl-evp SHA3-512", openssl_evp_checksum, result_file, EVP_sha3_512(), (const uint8_t*)input, input_len, output);
            }
            #endif // INCLUDE_OPENSSL

            else if (strcmp(token, "keccak224") == 0) {
                BENCHMARK(iterations, "hasha KECCAK-224", keccak_224, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak256") == 0) {
                BENCHMARK(iterations, "hasha KECCAK-256", keccak_256, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak384") == 0) {
                BENCHMARK(iterations, "hasha KECCAK-384", keccak_384, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strcmp(token, "keccak512") == 0) {
                BENCHMARK(iterations, "hasha KECCAK-512", keccak_512, result_file, (const uint8_t*)input, input_len, output);
            }
            else if (strncmp(token, "blake3_", 7) == 0) {
                char *endptr;
                long digest_bits = strtol(token + 7, &endptr, 10);
                if ((token + 7) == endptr || digest_bits <= 0) {
                    fprintf(stderr, "Invalid BLAKE3 digest length in token '%s'\n", token);
                } else {
                    size_t digest_bytes = HASHA_bB(digest_bits);
                    char benchname[64];
                    snprintf(benchname, sizeof(benchname), "hasha BLAKE3-%ld", digest_bits);
                    BENCHMARK(iterations, benchname, blake3, result_file, (const uint8_t*)input, input_len, output, digest_bytes);
                }
            }
            else {
                fprintf(stderr, "Unsupported algorithm: %s\n", token);
            }
            token = strtok(NULL, " ,");
        }
        free(algos_copy);
    }

    if (result_file) {
        fclose(result_file);
    }
    
    printf("\nBenchmark Complete!\n");
    return 0;
}
