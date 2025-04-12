#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#
#include "../include/hasha/hasha.h"
#include "../include/hasha/internal/error.h"

static char *ha_bench_error_strings[] = {
#define UNSUPPORTED_ERR 0
    "unsupported %s",
#define INVALID_ERR 1
    "invalid %s",
#define UNEXPECTED_ERR 2
    "unexpected %s",
#define MISSING_ERR 3
    "missing %s",
#define BASIC_ERROR 4
    "error %s",
#define ARG_ERROR 5
    "argument error: %s",
#define INVALID_DIGEST_LEN_ERROR 6
    "invalid %s digest length in token: '%s'",
};

// #define INCLUDE_OPENSSL

#define BENCHMARK(ITERATIONS, LABEL, FUNC, FILE_, ...)                    \
  do {                                                                    \
    struct timespec start, end;                                           \
    clock_gettime(CLOCK_MONOTONIC, &start);                               \
    for (int i = 0; i < (ITERATIONS); ++i) { FUNC(__VA_ARGS__); }         \
    clock_gettime(CLOCK_MONOTONIC, &end);                                 \
    long long start_us = start.tv_sec * 1000000LL + start.tv_nsec / 1000; \
    long long end_us   = end.tv_sec * 1000000LL + end.tv_nsec / 1000;     \
    long long time_taken_us       = end_us - start_us;                    \
    double    time_taken_s        = (double)time_taken_us / 1000000.0;    \
    double avg_time_per_iteration = (double)time_taken_us / (ITERATIONS); \
    printf(                                                               \
        "%s: Total time: %lld us (%lf s), Avg per iteration: %.2f us\n",  \
        LABEL, time_taken_us, time_taken_s, avg_time_per_iteration);      \
    if (FILE_)                                                            \
    {                                                                     \
      fprintf(FILE_, "%s,%lld,%lf,%.2f\n", LABEL, time_taken_us,          \
              time_taken_s, avg_time_per_iteration);                      \
    }                                                                     \
  } while (0)

// Function to display help/usage information
HA_PRVFUN void print_usage(const char *prog_name)
{
  printf("Usage: %s [OPTIONS]\n", prog_name);
  printf("\nSupported algorithms:\n");
  printf(
      "  crc32, md5, sha1, sha224, sha256, sha384, sha512, "
      "sha512_224, "
      "sha512_256,\n");
  printf(
      "  sha3_224, sha3_256, sha3_384, sha3_512, keccak224, "
      "keccak256, "
      "keccak384, keccak512\n");
  printf(
      "  blake2s_<digestlen(8...256)>"
      "  blake2s_<digestlen(8...512)>"
      "  blake3_<digestlen>\n");
  printf("Options:\n");
  printf(
      "  -t, --iters NUM      Number of iterations for benchmarking "
      "(default: 1000000)\n");
  printf(
      "  -i, --input STRING   Input string to hash (default: "
      "'hello')\n");
  printf("  -f, --file PATH      Input file path to hash\n");
  printf(
      "  -a, --algos STRING   Space- (or comma-) separated list of "
      "algorithms to benchmark (default: all)\n");
  printf("  -r, --svres PATH     Save benchmark results to a file\n");
  printf("  -h, --help           Show this help message\n");
}

// Helper: trim leading and trailing whitespace
HA_PRVFUN char *trim(char *str)
{
  while (isspace((unsigned char)*str)) str++;
  if (*str == 0) return str;
  char *end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;
  *(end + 1) = '\0';
  return str;
}

// Helper: get file size
HA_PRVFUN size_t get_file_sz(FILE *file)
{
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);
  return file_size;
}

// Helper: read file content
HA_PRVFUN void file_bufread(char *content, size_t sz, size_t bufsz,
                            FILE *file)
{
  size_t to_read = bufsz, total_read = 0, bytes_read = 0;
  /* fully read */
  if (bufsz == 0)
  {
    bytes_read = fread(content, 1, sz, file);
    return;
  }

  while (total_read < sz)
  {
    if (total_read + to_read > sz) to_read = sz - total_read;
    bytes_read = fread(content + total_read, 1, to_read, file);
    if (bytes_read == 0) break;  // End-of-file or read error.
    total_read += bytes_read;
  }

  if (total_read < sz + 1)
    content[sz] = '\0';  // Null-terminate the string
}

int main(int argc, char *argv[])
{
  int                  iterations = 1;        // Default iterations
  const char          *input      = "hello";  // Default input string
  const char          *algos      = "all";  // Default: run all algorithms
  const char          *file_path  = NULL;   // Default: (null)
  const char          *save_file  = NULL;   // Default: (null)

  static struct option long_options[] = {
      {"iters", required_argument, 0, 't'},
      {"input", required_argument, 0, 'i'},
      { "file", required_argument, 0, 'f'},
      {"algos", required_argument, 0, 'a'},
      {"svres", required_argument, 0, 'r'},
      { "help",       no_argument, 0, 'h'},
      {      0,                 0, 0,   0}
  };

  int opt, option_index = 0;
  while ((opt = getopt_long(argc, argv, "t:i:a:h:r:f:", long_options,
                            &option_index)) != -1)
  {
    switch (opt)
    {
      case 't':
        iterations = atoi(optarg);
        if (iterations <= 0)
        {
          char errbuf[256];
          snprintf(errbuf, sizeof(errbuf),
                   "invalid number of iterations: %s", optarg);
          ha_throw_error(ha_curpos, ha_bench_error_strings[ARG_ERROR],
                         errbuf);
          return 1;
        }
        break;
      case 'i':
        input = optarg;
        break;
      case 'f':
        file_path = optarg;
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

  FILE  *file;
  size_t file_size   = 0;
  int    file_opened = 0;

  if (file_path)
  {
    file = fopen(file_path, "rb");
    if (!file)
    {
      perror("fopen()");
      ha_throw_error(ha_curpos, ha_bench_error_strings[BASIC_ERROR],
                     "opening file");
      return 1;
    }
    file_opened = 1;
    file_size   = get_file_sz(file);
    input       = malloc(file_size + 1);
    if (!input)
    {
      perror("malloc()");
      ha_throw_error(ha_curpos, ha_bench_error_strings[BASIC_ERROR],
                     "memory allocating");
      fclose(file);
      return 1;
    }

    file_bufread((char *)input, file_size, 8192, file);
    fclose(file);
  }

  FILE *result_file = NULL;
  if (save_file)
  {
    result_file = fopen(save_file, "w");
    if (!result_file)
    {
      perror("fopen()");
      ha_throw_error(ha_curpos, ha_bench_error_strings[BASIC_ERROR],
                     "opening file");
      return 1;
    }
    fprintf(result_file,
            "Algorithm,Time (us),Total Time (s),Avg Time per Iteration "
            "(us)\n");
  }

  size_t input_len = strlen(input);
  printf(
      "Running benchmarks with input size %zu bytes, iterations: "
      "%d\n",
      input_len, iterations);
  printf("Selected algorithms: %s\n\n", algos);

  uint8_t output[512];

  // If "all" was passed, run a fixed set of benchmarks
  if (strcmp(algos, "all") == 0)
  {
    BENCHMARK(iterations, "CRC32", ha_crc32_hash, result_file,
              (const uint8_t *)input, input_len);
    BENCHMARK(iterations, "MD5", ha_md5_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA1", ha_sha1_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA224", ha_sha2_224_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA256", ha_sha2_256_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA384", ha_sha2_384_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA512", ha_sha2_512_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA512/224", ha_sha2_512_224_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA512/256", ha_sha2_512_256_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA3-224", ha_sha3_224_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA3-256", ha_sha3_256_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA3-384", ha_sha3_384_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "SHA3-512", ha_sha3_512_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-224", ha_keccak_224_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-256", ha_keccak_256_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-384", ha_keccak_384_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "KECCAK-512", ha_keccak_512_hash, result_file,
              (const uint8_t *)input, input_len, output);
    BENCHMARK(iterations, "BLAKE2S-128", ha_blake2s_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(128));
    BENCHMARK(iterations, "BLAKE2S-160", ha_blake2s_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(160));
    BENCHMARK(iterations, "BLAKE2S-256", ha_blake2s_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(256));
    BENCHMARK(iterations, "BLAKE2B-128", ha_blake2b_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(128));
    BENCHMARK(iterations, "BLAKE2B-160", ha_blake2b_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(160));
    BENCHMARK(iterations, "BLAKE2B-256", ha_blake2b_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(256));
    BENCHMARK(iterations, "BLAKE2B-512", ha_blake2b_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(512));
    BENCHMARK(iterations, "BLAKE3-224", ha_blake3_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(224));
    BENCHMARK(iterations, "BLAKE3-256", ha_blake3_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(256));
    BENCHMARK(iterations, "BLAKE3-384", ha_blake3_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(384));
    BENCHMARK(iterations, "BLAKE3-512", ha_blake3_hash, result_file,
              (const uint8_t *)input, input_len, output, ha_bB(512));
  }
  else
  {
    // Tokenize the provided algorithm string (using both space and
    // comma as delimiters)
    char *algos_copy = strdup(algos);
    char *token      = strtok(algos_copy, " ,");
    while (token)
    {
      token = trim(token);
      if (strcmp(token, "crc32") == 0)
      {
        BENCHMARK(iterations, "hasha CRC32", ha_crc32_hash, result_file,
                  (const uint8_t *)input, input_len);
      }
      else if (strcmp(token, "md5") == 0)
      {
        BENCHMARK(iterations, "hasha MD5", ha_md5_hash, result_file,
                  (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha1") == 0)
      {
        BENCHMARK(iterations, "hasha SHA1", ha_sha1_hash, result_file,
                  (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha224") == 0)
      {
        BENCHMARK(iterations, "hasha SHA224", ha_sha2_224_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha256") == 0)
      {
        BENCHMARK(iterations, "hasha SHA256", ha_sha2_256_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha384") == 0)
      {
        BENCHMARK(iterations, "hasha SHA384", ha_sha2_384_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha512") == 0)
      {
        BENCHMARK(iterations, "hasha SHA512", ha_sha2_512_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha512_224") == 0)
      {
        BENCHMARK(iterations, "hasha SHA512/224", ha_sha2_512_224_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha512_256") == 0)
      {
        BENCHMARK(iterations, "hasha SHA512/256", ha_sha2_512_256_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }

      else if (strcmp(token, "sha3_224") == 0)
      {
        BENCHMARK(iterations, "hasha SHA3-224", ha_sha3_224_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha3_256") == 0)
      {
        BENCHMARK(iterations, "hasha SHA3-256", ha_sha3_256_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha3_384") == 0)
      {
        BENCHMARK(iterations, "hasha SHA3-384", ha_sha3_384_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "sha3_512") == 0)
      {
        BENCHMARK(iterations, "hasha SHA3-512", ha_sha3_512_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "keccak224") == 0)
      {
        BENCHMARK(iterations, "hasha KECCAK-224", ha_keccak_224_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "keccak256") == 0)
      {
        BENCHMARK(iterations, "hasha KECCAK-256", ha_keccak_256_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "keccak384") == 0)
      {
        BENCHMARK(iterations, "hasha KECCAK-384", ha_keccak_384_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "keccak512") == 0)
      {
        BENCHMARK(iterations, "hasha KECCAK-512", ha_keccak_512_hash,
                  result_file, (const uint8_t *)input, input_len, output);
      }
      else if (strcmp(token, "keccakf1600") == 0)
      {
        uint64_t state[200] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
        BENCHMARK(iterations, "KECCAKF-1600", ha_keccakf1600, result_file,
                  state);
      }
      else if (strncmp(token, "blake2s_", 7) == 0)
      {
        char *endptr;
        long  digest_bits = strtol(token + 8, &endptr, 10);
        if ((token + 7) == endptr || digest_bits <= 0)
        {
          ha_throw_error(ha_curpos,
                         ha_bench_error_strings[INVALID_DIGEST_LEN_ERROR],
                         "blake2s", token);
        }
        else
        {
          size_t digest_bytes = ha_bB(digest_bits);
          char   benchname[64];
          snprintf(benchname, sizeof(benchname), "hasha BLAKE2S-%ld",
                   digest_bits);
          BENCHMARK(iterations, benchname, ha_blake2s_hash, result_file,
                    (const uint8_t *)input, input_len, output,
                    digest_bytes);
        }
      }
      else if (strncmp(token, "blake2b_", 7) == 0)
      {
        char *endptr;
        long  digest_bits = strtol(token + 8, &endptr, 10);
        if ((token + 7) == endptr || digest_bits <= 0)
        {
          ha_throw_error(ha_curpos,
                         ha_bench_error_strings[INVALID_DIGEST_LEN_ERROR],
                         "blake2b", token);
        }
        else
        {
          size_t digest_bytes = ha_bB(digest_bits);
          char   benchname[64];
          snprintf(benchname, sizeof(benchname), "hasha BLAKE2B-%ld",
                   digest_bits);
          BENCHMARK(iterations, benchname, ha_blake2b_hash, result_file,
                    (const uint8_t *)input, input_len, output,
                    digest_bytes);
        }
      }
      else if (strncmp(token, "blake3_", 7) == 0)
      {
        char *endptr;
        long  digest_bits = strtol(token + 7, &endptr, 10);
        if ((token + 7) == endptr || digest_bits <= 0)
        {
          ha_throw_error(ha_curpos,
                         ha_bench_error_strings[INVALID_DIGEST_LEN_ERROR],
                         "blake3", token);
        }
        else
        {
          size_t digest_bytes = ha_bB(digest_bits);
          char   benchname[64];
          snprintf(benchname, sizeof(benchname), "hasha BLAKE3-%ld",
                   digest_bits);
          BENCHMARK(iterations, benchname, ha_blake3_hash, result_file,
                    (const uint8_t *)input, input_len, output,
                    digest_bytes);
        }
      }
      else
      {
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "algorithm: %s", token);
        ha_throw_error(ha_curpos, ha_bench_error_strings[UNSUPPORTED_ERR],
                       errbuf);
      }
      token = strtok(NULL, " ,");
    }
    free(algos_copy);
  }

  if (result_file) fclose(result_file);
  if (file_opened) free((void *)input);

  printf("\nBenchmark Complete!\n");
  return 0;
}
