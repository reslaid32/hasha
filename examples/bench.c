#include "../include/hasha/all.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

// Function to print hashes
void print_hash(const uint8_t *hash, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Function to compare hashes
int compare_hash(const uint8_t *hash, const char *expected_hash, size_t hash_len) {
    char hash_str[hash_len * 2 + 1];
    for (size_t i = 0; i < hash_len; ++i) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[hash_len * 2] = '\0';
    return strcmp(hash_str, expected_hash);
}

// Benchmark function for a hash with nanosecond precision
void benchmark_hash(void (*hash_function)(const uint8_t*, size_t, uint8_t*), const uint8_t* input, size_t input_len, uint8_t* output, const char* hash_name) {
    const int ITERATIONS = 1000000;
    struct timespec start, end;
    
    // Start benchmarking
    clock_gettime(CLOCK_MONOTONIC, &start); // Get start time
    for (int i = 0; i < ITERATIONS; ++i) {
        hash_function(input, input_len, output); // Run hash function
    }
    clock_gettime(CLOCK_MONOTONIC, &end); // Get end time
    
    // Calculate total time taken in nanoseconds
    long long start_ns = start.tv_sec * 1000000000LL + start.tv_nsec;
    long long end_ns = end.tv_sec * 1000000000LL + end.tv_nsec;
    long long time_taken_ns = end_ns - start_ns;
    double time_taken_s = (double)time_taken_ns / 1000000000.0;

    // Calculate average time per iteration
    double avg_time_per_iteration = (double)time_taken_ns / ITERATIONS;

    printf("%s: Total time: %lld nanoseconds (%lf seconds), Average time per iteration: %.2f nanoseconds\n", hash_name, time_taken_ns, time_taken_s, avg_time_per_iteration);
}

// Benchmark function for Blake3 with output size and nanosecond precision
void benchmark_blake_hash(void (*hash_function)(const uint8_t*, size_t, uint8_t*, size_t), const uint8_t* input, size_t input_len, uint8_t* output, size_t output_size, const char* hash_name) {
    const int ITERATIONS = 1000000;
    struct timespec start, end;

    // Start benchmarking
    clock_gettime(CLOCK_MONOTONIC, &start); // Get start time
    for (int i = 0; i < ITERATIONS; ++i) {
        hash_function(input, input_len, output, output_size); // Run hash function
    }
    clock_gettime(CLOCK_MONOTONIC, &end); // Get end time
    
    // Calculate total time taken in nanoseconds
    long long start_ns = start.tv_sec * 1000000000LL + start.tv_nsec;
    long long end_ns = end.tv_sec * 1000000000LL + end.tv_nsec;
    long long time_taken_ns = end_ns - start_ns;
    double time_taken_s = (double)time_taken_ns / 1000000000.0;

    // Calculate average time per iteration
    double avg_time_per_iteration = (double)time_taken_ns / ITERATIONS;

    printf("%s: Total time: %lld nanoseconds (%lf seconds), Average time per iteration: %.2f nanoseconds\n", hash_name, time_taken_ns, time_taken_s, avg_time_per_iteration);
}

void benchmark_checksum32(uint32_t (*hash_function)(const uint8_t*, size_t), const uint8_t* input, size_t input_len, const char* hash_name) {
    const int ITERATIONS = 1000000;
    struct timespec start, end;
    
    // Start benchmarking
    clock_gettime(CLOCK_MONOTONIC, &start); // Get start time
    for (int i = 0; i < ITERATIONS; ++i) {
        hash_function(input, input_len); // Run hash function
    }
    clock_gettime(CLOCK_MONOTONIC, &end); // Get end time
    
    // Calculate total time taken in nanoseconds
    long long start_ns = start.tv_sec * 1000000000LL + start.tv_nsec;
    long long end_ns = end.tv_sec * 1000000000LL + end.tv_nsec;
    long long time_taken_ns = end_ns - start_ns;
    double time_taken_s = (double)time_taken_ns / 1000000000.0;

    // Calculate average time per iteration
    double avg_time_per_iteration = (double)time_taken_ns / ITERATIONS;

    printf("%s: Total time: %lld nanoseconds (%lf seconds), Average time per iteration: %.2f nanoseconds\n", hash_name, time_taken_ns, time_taken_s, avg_time_per_iteration);
}

// Run all unit tests and benchmarks
void runbench() {
    const char *input = "hello";
    size_t input_len = strlen(input);

    benchmark_checksum32(crc32, (const uint8_t*)input, input_len, "CRC32");

    // MD5
    uint8_t md5_output[MD5_DIGEST_SIZE];
    benchmark_hash(md5, (const uint8_t*)input, input_len, md5_output, "MD5");

    // SHA1
    uint8_t sha1_output[SHA1_DIGEST_SIZE];
    benchmark_hash(sha1, (const uint8_t*)input, input_len, sha1_output, "SHA1");

    // SHA2-224
    uint8_t sha2_224_output[SHA2_224_DIGEST_SIZE];
    benchmark_hash(sha2_224, (const uint8_t*)input, input_len, sha2_224_output, "SHA2-224");

    // SHA2-256
    uint8_t sha2_256_output[SHA2_256_DIGEST_SIZE];
    benchmark_hash(sha2_256, (const uint8_t*)input, input_len, sha2_256_output, "SHA2-256");

    // SHA2-384
    uint8_t sha2_384_output[SHA2_384_DIGEST_SIZE];
    benchmark_hash(sha2_384, (const uint8_t*)input, input_len, sha2_384_output, "SHA2-384");

    // SHA2-512
    uint8_t sha2_512_output[SHA2_512_DIGEST_SIZE];
    benchmark_hash(sha2_512, (const uint8_t*)input, input_len, sha2_512_output, "SHA2-512");

    // SHA2-512/224
    uint8_t sha2_512_224_output[SHA2_512_224_DIGEST_SIZE];
    benchmark_hash(sha2_512_224, (const uint8_t*)input, input_len, sha2_512_224_output, "SHA2-512/224");

    // SHA2-512/256
    uint8_t sha2_512_256_output[SHA2_512_256_DIGEST_SIZE];
    benchmark_hash(sha2_512_256, (const uint8_t*)input, input_len, sha2_512_256_output, "SHA2-512/256");

    // SHA3-224
    uint8_t sha3_224_output[SHA3_224_DIGEST_SIZE];
    benchmark_hash(sha3_224, (const uint8_t*)input, input_len, sha3_224_output, "SHA3-224");

    // SHA3-256
    uint8_t sha3_256_output[SHA3_256_DIGEST_SIZE];
    benchmark_hash(sha3_256, (const uint8_t*)input, input_len, sha3_256_output, "SHA3-256");

    // SHA3-384
    uint8_t sha3_384_output[SHA3_384_DIGEST_SIZE];
    benchmark_hash(sha3_384, (const uint8_t*)input, input_len, sha3_384_output, "SHA3-384");

    // SHA3-512
    uint8_t sha3_512_output[SHA3_512_DIGEST_SIZE];
    benchmark_hash(sha3_512, (const uint8_t*)input, input_len, sha3_512_output, "SHA3-512");

    // KECCAK-224
    uint8_t keccak_224_output[KECCAK_224_DIGEST_SIZE];
    benchmark_hash(keccak_224, (const uint8_t*)input, input_len, keccak_224_output, "KECCAK-224");

    // KECCAK-256
    uint8_t keccak_256_output[KECCAK_256_DIGEST_SIZE];
    benchmark_hash(keccak_256, (const uint8_t*)input, input_len, keccak_256_output, "KECCAK-256");

    // KECCAK-384
    uint8_t keccak_384_output[KECCAK_384_DIGEST_SIZE];
    benchmark_hash(keccak_384, (const uint8_t*)input, input_len, keccak_384_output, "KECCAK-384");

    // KECCAK-512
    uint8_t keccak_512_output[KECCAK_512_DIGEST_SIZE];
    benchmark_hash(keccak_512, (const uint8_t*)input, input_len, keccak_512_output, "KECCAK-512");
    
    uint8_t blake3_224_output[HASHA_bB(224)];
    benchmark_blake_hash(blake3, (const uint8_t*)input, input_len, blake3_224_output, sizeof(blake3_224_output), "BLAKE3-224");

    uint8_t blake3_256_output[HASHA_bB(256)];
    benchmark_blake_hash(blake3, (const uint8_t*)input, input_len, blake3_256_output, sizeof(blake3_256_output), "BLAKE3-256");

    uint8_t blake3_384_output[HASHA_bB(384)];
    benchmark_blake_hash(blake3, (const uint8_t*)input, input_len, blake3_384_output, sizeof(blake3_384_output), "BLAKE3-384");

    uint8_t blake3_512_output[HASHA_bB(512)];
    benchmark_blake_hash(blake3, (const uint8_t*)input, input_len, blake3_512_output, sizeof(blake3_512_output), "BLAKE3-512");

    uint8_t blake3_1024_output[HASHA_bB(1024)];
    benchmark_blake_hash(blake3, (const uint8_t*)input, input_len, blake3_1024_output, sizeof(blake3_1024_output), "BLAKE3-1024");

    printf("\nBenchmark Complete!\n");
}

int main() {
    runbench();
    return 0;
}
