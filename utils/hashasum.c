#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hasha/all.h"

void print_digest(const uint8_t *digest, size_t size)
{
  for (size_t i = 0; i < size; ++i) { printf("%02x", digest[i]); }
  printf("\n");
}

void print_usage(const char *program_name)
{
  printf("Usage: %s <algorithm> <data_source> [data]\n", program_name);
  printf("\nSupported algorithms:\n");
  printf(
      "  crc32, md5, sha1, sha224, sha256, sha384, sha512, sha512_224, "
      "sha512_256,\n");
  printf(
      "  sha3_224, sha3_256, sha3_384, sha3_512, keccak224, keccak256, "
      "keccak384, keccak512\n");
  printf("  blake3_<digestlen>\n");
  printf("\nData source options:\n");
  printf("  -s <string>        Hash a string provided as an argument\n");
  printf("  -f <file_path>     Hash the contents of a file\n");
  printf("  -stdin             Hash data from standard input\n");
  printf("\nVerify mode:\n");
  printf(
      "  -verify <hash>     Verify the result against the expected "
      "hash\n");
}

void hash_data(const char *algorithm, const uint8_t *data, size_t length,
               uint8_t *digest, size_t *digest_size)
{
  if (strcmp(algorithm, "crc32") == 0)
  {
    uint32_t crc = crc32_oneshot(data, length);
    printf("%08x\n", crc);
    return;
  }
  else if (strcmp(algorithm, "md5") == 0)
  {
    *digest_size = MD5_DIGEST_SIZE;
    md5_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha1") == 0)
  {
    *digest_size = SHA1_DIGEST_SIZE;
    sha1_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha224") == 0)
  {
    *digest_size = SHA2_224_DIGEST_SIZE;
    sha2_224_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha256") == 0)
  {
    *digest_size = SHA2_256_DIGEST_SIZE;
    sha2_256_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha384") == 0)
  {
    *digest_size = SHA2_384_DIGEST_SIZE;
    sha2_384_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha512") == 0)
  {
    *digest_size = SHA2_512_DIGEST_SIZE;
    sha2_512_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha512_224") == 0)
  {
    *digest_size = SHA2_512_224_DIGEST_SIZE;
    sha2_512_224_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha512_256") == 0)
  {
    *digest_size = SHA2_512_256_DIGEST_SIZE;
    sha2_512_256_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_224") == 0)
  {
    *digest_size = SHA3_224_DIGEST_SIZE;
    sha3_224_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_256") == 0)
  {
    *digest_size = SHA3_256_DIGEST_SIZE;
    sha3_256_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_384") == 0)
  {
    *digest_size = SHA3_384_DIGEST_SIZE;
    sha3_384_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "sha3_512") == 0)
  {
    *digest_size = SHA3_512_DIGEST_SIZE;
    sha3_512_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak224") == 0)
  {
    *digest_size = KECCAK_224_DIGEST_SIZE;
    keccak_224_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak256") == 0)
  {
    *digest_size = KECCAK_256_DIGEST_SIZE;
    keccak_256_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak384") == 0)
  {
    *digest_size = KECCAK_384_DIGEST_SIZE;
    keccak_384_oneshot(data, length, digest);
  }
  else if (strcmp(algorithm, "keccak512") == 0)
  {
    *digest_size = KECCAK_512_DIGEST_SIZE;
    keccak_512_oneshot(data, length, digest);
  }
  else if (strncmp(algorithm, "blake3_", 7) == 0)
  {
    const char *len_str = algorithm + 7;
    char *end;
    long len     = strtol(len_str, &end, 10);
    *digest_size = HASHA_bB(len);
    blake3_oneshot(data, length, digest, *digest_size);
  }
  else
  {
    fprintf(stderr, "Error: Unsupported algorithm '%s'\n", algorithm);
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

  if (strcmp(calculated_hash, expected_hash) == 0)
  {
    printf("Verification successful: Hash matches.\n");
    return 1;
  }
  else
  {
    printf("Verification failed: Hash does not match.\n");
    return 0;
  }
}

int main(int argc, char *argv[])
{
  if (argc < 3)
  {
    hashaver_t hashav = hashaver();
    printf("libhasha version: %u.%u.%u\n", hashav.major, hashav.minor,
           hashav.patch);
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
      fprintf(stderr, "Error: Missing string data\n");
      return EXIT_FAILURE;
    }
    data   = (uint8_t *)argv[3];
    length = strlen((char *)data);
  }
  else if (strcmp(data_source, "-f") == 0)
  {
    if (argc < 4)
    {
      fprintf(stderr, "Error: Missing file path\n");
      return EXIT_FAILURE;
    }
    FILE *file = fopen(argv[3], "rb");
    if (!file)
    {
      perror("Error opening file");
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
      perror("Error allocating memory");
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
      perror("Error allocating memory");
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
          perror("Error reallocating memory");
          return EXIT_FAILURE;
        }
      }
      data[length++] = (uint8_t)ch;
    }
    needFree = 1;
  }
  else
  {
    fprintf(stderr, "Error: Unsupported data source '%s'\n", data_source);
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
