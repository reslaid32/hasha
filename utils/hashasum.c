#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hasha/hasha.h"
#include "../include/hasha/internal/error.h"

static char *ha_sum_error_strings[] = {
#define HASH_MATCH_NO 0
    "hash does not match",
#define HASH_MATCH_YES 1
    "hash matches",
#define UNEXPECTED_ERR 2
    "unexpected %s",
#define MISSING_ERR 3
    "missing %s",
#define BASIC_ERROR 4
    "error %s",
#define UNSUPPORTED_ERR 5
    "unsupported %s",
};

void print_digest(const ha_digest_t digest, size_t size)
{
  for (size_t i = 0; i < size; ++i) { printf("%02x", digest[i]); }
  printf("\n");
}

void print_usage(const char *execu)
{
  printf("Usage: %s <algorithm> <data_source> [data]\n", execu);
  printf("\nSupported algorithms:\n");
  printf(
      "  crc32, md5, sha1, sha224, sha256, sha384, sha512, sha512_224, "
      "sha512_256,\n");
  printf(
      "  sha3_224, sha3_256, sha3_384, sha3_512, keccak224, keccak256, "
      "keccak384, keccak512\n");
  printf(
      "  blake2s_<digestlen(8...256)>"
      "  blake2s_<digestlen(8...512)>"
      "  blake3_<digestlen>\n");
  printf("\nData source options:\n");
  printf("  -s <string>        Hash a string provided as an argument\n");
  printf("  -f <file_path>     Hash the contents of a file\n");
  printf("  -stdin             Hash data from standard input\n");
  printf("\nVerify mode:\n");
  printf(
      "  -verify <hash>     Verify the result against the expected "
      "hash\n");
}

void hash_data(const char *algorithm, ha_inbuf_t data, size_t length,
               ha_digest_t digest, size_t *digest_size)
{
  if (strcmp(algorithm, "crc32") == 0)
  {
    uint32_t crc = ha_crc32_hash(data, length);
    printf("%08x\n", crc);
    return;
  }
  else if (strcmp(algorithm, "md5") == 0)
  {
    *digest_size = HA_MD5_DIGEST_SIZE;
    ha_md5_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha1") == 0)
  {
    *digest_size = HA_SHA1_DIGEST_SIZE;
    ha_sha1_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha224") == 0)
  {
    *digest_size = HA_SHA2_224_DIGEST_SIZE;
    ha_sha2_224_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha256") == 0)
  {
    *digest_size = HA_SHA2_256_DIGEST_SIZE;
    ha_sha2_256_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha384") == 0)
  {
    *digest_size = HA_SHA2_384_DIGEST_SIZE;
    ha_sha2_384_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha512") == 0)
  {
    *digest_size = HA_SHA2_512_DIGEST_SIZE;
    ha_sha2_512_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha512_224") == 0)
  {
    *digest_size = HA_SHA2_512_224_DIGEST_SIZE;
    ha_sha2_512_224_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha512_256") == 0)
  {
    *digest_size = HA_SHA2_512_256_DIGEST_SIZE;
    ha_sha2_512_256_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_224") == 0)
  {
    *digest_size = HA_SHA3_224_DIGEST_SIZE;
    ha_sha3_224_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_256") == 0)
  {
    *digest_size = HA_SHA3_256_DIGEST_SIZE;
    ha_sha3_256_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_384") == 0)
  {
    *digest_size = HA_SHA3_384_DIGEST_SIZE;
    ha_sha3_384_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_512") == 0)
  {
    *digest_size = HA_SHA3_512_DIGEST_SIZE;
    ha_sha3_512_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak224") == 0)
  {
    *digest_size = HA_KECCAK_224_DIGEST_SIZE;
    ha_keccak_224_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak256") == 0)
  {
    *digest_size = HA_KECCAK_256_DIGEST_SIZE;
    ha_keccak_256_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak384") == 0)
  {
    *digest_size = HA_KECCAK_384_DIGEST_SIZE;
    ha_keccak_384_hash(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak512") == 0)
  {
    *digest_size = HA_KECCAK_512_DIGEST_SIZE;
    ha_keccak_512_hash(data, length, digest);
  }
  else if (strncmp(algorithm, "blake2b_", 7) == 0)
  {
    const char *len_str = algorithm + 8;
    char *end;
    long len     = strtol(len_str, &end, 10);
    *digest_size = ha_bB(len);
    ha_blake2b_hash(data, length, digest, *digest_size);
  }
  else if (strncmp(algorithm, "blake2s_", 7) == 0)
  {
    const char *len_str = algorithm + 8;
    char *end;
    long len     = strtol(len_str, &end, 10);
    *digest_size = ha_bB(len);
    ha_blake2s_hash(data, length, digest, *digest_size);
  }
  else if (strncmp(algorithm, "blake3_", 7) == 0)
  {
    const char *len_str = algorithm + 7;
    char *end;
    long len     = strtol(len_str, &end, 10);
    *digest_size = ha_bB(len);
    ha_blake3_hash(data, length, digest, *digest_size);
  }
  else
  {
    ha_throw_error(ha_curpos, ha_sum_error_strings[UNSUPPORTED_ERR],
                   "algorithm '%s'", algorithm);
    exit(EXIT_FAILURE);
  }
}

int verify_hash(const uint8_t *calculated_digest, size_t digest_size,
                const char *expected_hash)
{
  char calculated_hash[2 * digest_size + 1];
  for (size_t i = 0; i < digest_size; ++i)
  {
    sprintf(&calculated_hash[2 * i], "%02x", calculated_digest[i]);
  }

  int hashmatch = HASH_MATCH_NO;
  if (strcmp(calculated_hash, expected_hash) == 0)
    hashmatch = HASH_MATCH_YES;

  ha_throw(1, ha_curpos, "info", "verification: %s",
           ha_sum_error_strings[hashmatch]);
  return hashmatch;
}

int main(int argc, char *argv[])
{
  if (argc < 3)
  {
    ha_version_t hashav = ha_version();
    ha_throw(1, ha_curpos, "info", "libhasha version: %u.%u.%u",
             hashav.major, hashav.minor, hashav.patch);
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *algorithm   = argv[1];
  const char *data_source = argv[2];
  uint8_t *data           = NULL;
  size_t length           = 0;
  uint8_t digest[64];  // Maximum digest size
  size_t digest_size        = 0;
  int needFree              = 0;
  const char *expected_hash = NULL;

  if (argc > 4 && strcmp(argv[4], "-verify") == 0)
  {
    expected_hash = argv[5];
  }

  if (strcmp(data_source, "-s") == 0)
  {
    if (argc < 4)
    {
      ha_throw_error(ha_curpos, ha_sum_error_strings[MISSING_ERR],
                     "string");
      return EXIT_FAILURE;
    }
    data   = (uint8_t *)argv[3];
    length = strlen((char *)data);
  }
  else if (strcmp(data_source, "-f") == 0)
  {
    if (argc < 4)
    {
      ha_throw_error(ha_curpos, ha_sum_error_strings[MISSING_ERR], "file");
      return EXIT_FAILURE;
    }
    FILE *file = fopen(argv[3], "rb");
    if (!file)
    {
      ha_throw_error(ha_curpos, ha_sum_error_strings[BASIC_ERROR],
                     "opening file");
      perror("fopen()");
      return EXIT_FAILURE;
    }

    // Seek to the end to get the file length
    fseek(file, 0, SEEK_END);
    length = ftell(file);      // Get file length
    fseek(file, 0, SEEK_SET);  // Reset file pointer to the beginning

    // Allocate memory to read the entire file
    data = (uint8_t *)malloc(length);
    if (!data)
    {
      ha_throw_error(ha_curpos, ha_sum_error_strings[BASIC_ERROR],
                     "memory allocating");
      perror("malloc()");
      fclose(file);
      return EXIT_FAILURE;
    }
    needFree = 1;

    // Read the entire file into memory
    fread(data, 1, length, file);
    fclose(file);
  }
  else if (strcmp(data_source, "-stdin") == 0)
  {
    size_t capacity = 1024;
    data            = (uint8_t *)malloc(capacity);
    if (!data)
    {
      ha_throw_error(ha_curpos, ha_sum_error_strings[BASIC_ERROR],
                     "memory allocating");
      perror("malloc()");
      return EXIT_FAILURE;
    }
    length = 0;
    int ch;
    while ((ch = getchar()) != EOF)
    {
      if (length >= capacity)
      {
        capacity *= 2;
        data = (uint8_t *)realloc(data, capacity);
        if (!data)
        {
          ha_throw_error(ha_curpos, ha_sum_error_strings[BASIC_ERROR],
                         "memory reallocating");
          perror("realloc()");
          return EXIT_FAILURE;
        }
      }
      data[length++] = (uint8_t)ch;
    }
    needFree = 1;
  }
  else
  {
    ha_throw_error(ha_curpos, ha_sum_error_strings[UNSUPPORTED_ERR],
                   "data source '%s'", data_source);
    return EXIT_FAILURE;
  }

  // Calculate hash for the data (whether from stdin, file, or string)
  hash_data(algorithm, data, length, digest, &digest_size);

  // Verify hash if necessary
  if (expected_hash) { verify_hash(digest, digest_size, expected_hash); }
  else { print_digest(digest, digest_size); }

  if (needFree) { free(data); }

  return EXIT_SUCCESS;
}
