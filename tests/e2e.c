
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hasha/hasha.h"
#include "../include/hasha/internal/error.h"

static const char *input = "hello";
static size_t      input_len;
static int         debug = 0;

#define __fprintf(expr, stream, ...)                                      \
  if (expr) { fprintf(stream, ##__VA_ARGS__); }

void e2e_0()
{
  if (!input_len) input_len = strlen(input);
  {
    uint32_t crc = ha_crc32_hash((const uint8_t *)input, input_len);

    uint32_t expected_hash = 0x3610a686;

    assert(crc == expected_hash);
    __fprintf(debug, stdout, "crc:          passed\n");
  }
  {
    uint8_t output[HA_MD5_DIGEST_SIZE];

    ha_md5_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash = "5d41402abc4b2a76b9719d911017c592";

    assert(ha_cmphashstr(output, expected_hash, HA_MD5_DIGEST_SIZE) == 0);

    __fprintf(debug, stdout, "md5:          passed\n");
  }
  {
    uint8_t output[HA_SHA1_DIGEST_SIZE];

    ha_sha1_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA1_DIGEST_SIZE) == 0);

    __fprintf(debug, stdout, "sha1:         passed\n");
  }
  {
    uint8_t output[HA_SHA2_224_DIGEST_SIZE];

    ha_sha2_224_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA2_224_DIGEST_SIZE) ==
           0);

    __fprintf(debug, stdout, "sha2-224:     passed\n");
  }
  {
    uint8_t output[HA_SHA2_256_DIGEST_SIZE];

    ha_sha2_256_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA2_256_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "sha2-256:     passed\n");
  }
  {
    uint8_t output[HA_SHA2_384_DIGEST_SIZE];

    ha_sha2_384_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa901"
        "25a3c79f90397bdf5f6a13de828684f";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA2_384_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "sha2-384:     passed\n");
  }
  {
    uint8_t output[HA_SHA2_512_DIGEST_SIZE];

    ha_sha2_512_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72"
        "323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA2_512_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "sha2-512:     passed\n");
  }
  {
    uint8_t output[HA_SHA2_512_224_DIGEST_SIZE];

    ha_sha2_512_224_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c";

    assert(ha_cmphashstr(output, expected_hash,
                         HA_SHA2_512_224_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "sha2-512/224: passed\n");
  }
  {
    uint8_t output[HA_SHA2_512_256_DIGEST_SIZE];

    ha_sha2_512_256_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a";

    assert(ha_cmphashstr(output, expected_hash,
                         HA_SHA2_512_256_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "sha2-512/256: passed\n");
  }

  {
    uint8_t output[HA_SHA3_224_DIGEST_SIZE];

    ha_sha3_224_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA3_224_DIGEST_SIZE) ==
           0);

    __fprintf(debug, stdout, "sha3-224:     passed\n");
  }
  {
    uint8_t output[HA_SHA3_256_DIGEST_SIZE];

    ha_sha3_256_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA3_256_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "sha3-256:     passed\n");
  }
  {
    uint8_t output[HA_SHA3_384_DIGEST_SIZE];

    ha_sha3_384_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa133"
        "0ff07c0fddee54699a4c3ee0ee9d887";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA3_384_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "sha3-384:     passed\n");
  }
  {
    uint8_t output[HA_SHA3_512_DIGEST_SIZE];

    ha_sha3_512_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df8"
        "91d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976";

    assert(ha_cmphashstr(output, expected_hash, HA_SHA3_512_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "sha3-512:     passed\n");
  }
  {
    uint8_t output[HA_KECCAK_224_DIGEST_SIZE];

    ha_keccak_224_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "45524ec454bcc7d4b8f74350c4a4e62809fcb49bc29df62e61b69fa4";

    assert(ha_cmphashstr(output, expected_hash,
                         HA_KECCAK_224_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "keccak-224:   passed\n");
  }
  {
    uint8_t output[HA_KECCAK_256_DIGEST_SIZE];

    ha_keccak_256_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

    assert(ha_cmphashstr(output, expected_hash,
                         HA_KECCAK_256_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "keccak-256:   passed\n");
  }
  {
    uint8_t output[HA_KECCAK_384_DIGEST_SIZE];

    ha_keccak_384_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb4c"
        "d8e9c703b8f43e7277b59a5cd402175";

    assert(ha_cmphashstr(output, expected_hash,
                         HA_KECCAK_384_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "keccak-384:   passed\n");
  }
  {
    uint8_t output[HA_KECCAK_512_DIGEST_SIZE];

    ha_keccak_512_hash((const uint8_t *)input, input_len, output);

    const char *expected_hash =
        "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d4"
        "7de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976";

    assert(ha_cmphashstr(output, expected_hash,
                         HA_KECCAK_512_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "keccak-512:   passed\n");
  }
  {
    uint8_t output[ha_bB(128)];

    ha_blake2s_hash((const uint8_t *)input, input_len, output, ha_bB(128));

    const char *expected_hash = "96d539653dbf841c384b53d5f04658e5";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(128)) == 0);
    __fprintf(debug, stdout, "blake2s-128:  passed\n");
  }
  {
    uint8_t output[ha_bB(160)];

    ha_blake2s_hash((const uint8_t *)input, input_len, output, ha_bB(160));

    const char *expected_hash = "0fee8bbc1b2b15579499fec667487059abd72794";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(160)) == 0);
    __fprintf(debug, stdout, "blake2s-160:  passed\n");
  }
  {
    uint8_t output[HA_BLAKE2S_DIGEST_SIZE];

    ha_blake2s_hash((const uint8_t *)input, input_len, output,
                    HA_BLAKE2S_DIGEST_SIZE);

    const char *expected_hash =
        "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25";
    assert(ha_cmphashstr(output, expected_hash, HA_BLAKE2S_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "blake2s-256:  passed\n");
  }
  {
    uint8_t output[ha_bB(128)];

    ha_blake2b_hash((const uint8_t *)input, input_len, output, ha_bB(128));

    const char *expected_hash = "46fb7408d4f285228f4af516ea25851b";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(128)) == 0);
    __fprintf(debug, stdout, "blake2b-128:  passed\n");
  }
  {
    uint8_t output[ha_bB(160)];

    ha_blake2b_hash((const uint8_t *)input, input_len, output, ha_bB(160));

    const char *expected_hash = "b5531c7037f06c9f2947132a6a77202c308e8939";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(160)) == 0);
    __fprintf(debug, stdout, "blake2b-160:  passed\n");
  }
  {
    uint8_t output[ha_bB(256)];

    ha_blake2b_hash((const uint8_t *)input, input_len, output, ha_bB(256));

    const char *expected_hash =
        "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(256)) == 0);
    __fprintf(debug, stdout, "blake2b-256:  passed\n");
  }
  {
    uint8_t output[HA_BLAKE2B_DIGEST_SIZE];

    ha_blake2b_hash((const uint8_t *)input, input_len, output,
                    HA_BLAKE2B_DIGEST_SIZE);

    const char *expected_hash =
        "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65"
        "ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94";
    assert(ha_cmphashstr(output, expected_hash, HA_BLAKE2B_DIGEST_SIZE) ==
           0);
    __fprintf(debug, stdout, "blake2b-512:  passed\n");
  }
  {
    uint8_t output[ha_bB(224)];

    ha_blake3_hash((const uint8_t *)input, input_len, output, ha_bB(224));

    const char *expected_hash =
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c562";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(224)) == 0);
    __fprintf(debug, stdout, "blake3-224:   passed\n");
  }
  {
    uint8_t output[ha_bB(256)];

    ha_blake3_hash((const uint8_t *)input, input_len, output, ha_bB(256));

    const char *expected_hash =
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(256)) == 0);
    __fprintf(debug, stdout, "blake3-256:   passed\n");
  }
  {
    uint8_t output[ha_bB(384)];

    ha_blake3_hash((const uint8_t *)input, input_len, output, ha_bB(384));

    const char *expected_hash =
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe"
        "992405f0d785b599a2e3387f6d34d01";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(384)) == 0);
    __fprintf(debug, stdout, "blake3-384:   passed\n");
  }
  {
    uint8_t output[ha_bB(512)];

    ha_blake3_hash((const uint8_t *)input, input_len, output, ha_bB(512));

    const char *expected_hash =
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe"
        "992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338c";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(512)) == 0);
    __fprintf(debug, stdout, "blake3-512:   passed\n");
  }
  {
    uint8_t output[ha_bB(1024)];

    ha_blake3_hash((const uint8_t *)input, input_len, output, ha_bB(1024));

    const char *expected_hash =
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe"
        "992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338cc6"
        "8876568ab5c6e524abbcfe881e5b4e1ac9336f3f932d412248c9829536699f07a"
        "1b1ce35ffdfe0be5d00c083a8dfd29c9a4303d1374cd70e6abcec6e6b796c";
    assert(ha_cmphashstr(output, expected_hash, ha_bB(1024)) == 0);
    __fprintf(debug, stdout, "blake3-1024:  passed\n");
  }
}

void e2e_1()
{
  if (!input_len) input_len = strlen(input);

  size_t digest_maxsize = 1024;

#ifdef DIGEST_IN_HEAP
  uint8_t *digest = malloc(digest_maxsize);
#else
  uint8_t digest[digest_maxsize];
#endif

  ha_evp_phasher_t hasher = ha_evp_hasher_new();

  {
    ha_evp_hasher_init(hasher, HA_EVPTY_MD5, HA_MD5_DIGEST_SIZE);
    ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
    const char *expected_hash = "5d41402abc4b2a76b9719d911017c592";
    assert(ha_cmphashstr(digest, expected_hash, HA_MD5_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "md5:          passed\n");
    ha_evp_hasher_cleanup(hasher);
  }

  {
    ha_evp_hasher_init(hasher, HA_EVPTY_SHA1, HA_SHA1_DIGEST_SIZE);
    ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
    const char *expected_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    assert(ha_cmphashstr(digest, expected_hash, HA_SHA1_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "sha1:         passed\n");
    ha_evp_hasher_cleanup(hasher);
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_224_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_224_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-224:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_256_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982"
          "4";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_256_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-256:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_384_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa9"
          "0125a3c79f90397bdf5f6a13de828684f";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_384_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-384:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_512_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca"
          "72"
          "323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec04"
          "3";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_512_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-512:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_224_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_224_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-224:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_256_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f39"
          "2";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_256_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-256:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_384_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1"
          "33"
          "0ff07c0fddee54699a4c3ee0ee9d887";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_384_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-384:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_512_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6d"
          "f8"
          "91d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a8497"
          "6";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_512_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-512:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_224_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "45524ec454bcc7d4b8f74350c4a4e62809fcb49bc29df62e61b69fa4";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_224_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-224:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_256_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac"
          "8";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_256_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-256:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_384_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb"
          "4c"
          "d8e9c703b8f43e7277b59a5cd402175";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_384_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-384:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_512_DIGEST_SIZE);
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39"
          "d4"
          "7de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f97"
          "6";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_512_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-512:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2S, ha_bB(128));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash = "96d539653dbf841c384b53d5f04658e5";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(128)) == 0);
      __fprintf(debug, stdout, "blake2s-128:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2S, ha_bB(160));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "0fee8bbc1b2b15579499fec667487059abd72794";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(160)) == 0);
      __fprintf(debug, stdout, "blake2s-160:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2S, ha_bB(256));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca2"
          "5";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(256)) == 0);
      __fprintf(debug, stdout, "blake2s-256:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(128));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash = "46fb7408d4f285228f4af516ea25851b";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(128)) == 0);
      __fprintf(debug, stdout, "blake2b-128:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(160));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "b5531c7037f06c9f2947132a6a77202c308e8939";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(160)) == 0);
      __fprintf(debug, stdout, "blake2b-160:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(256));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72c"
          "f";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(256)) == 0);
      __fprintf(debug, stdout, "blake2b-256:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(512));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a"
          "65"
          "ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c9"
          "4";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(512)) == 0);
      __fprintf(debug, stdout, "blake2b-512:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(224));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c562";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(224)) == 0);
      __fprintf(debug, stdout, "blake3-224:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(256));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "f";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(256)) == 0);
      __fprintf(debug, stdout, "blake3-256:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(384));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "fe"
          "992405f0d785b599a2e3387f6d34d01";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(384)) == 0);
      __fprintf(debug, stdout, "blake3-384:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(512));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "fe"
          "992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338"
          "c";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(512)) == 0);
      __fprintf(debug, stdout, "blake3-512:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(1024));
      ha_evp_hash(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "fe"
          "992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338c"
          "c6"
          "8876568ab5c6e524abbcfe881e5b4e1ac9336f3f932d412248c9829536699f0"
          "7a"
          "1b1ce35ffdfe0be5d00c083a8dfd29c9a4303d1374cd70e6abcec6e6b796c";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(1024)) == 0);
      __fprintf(debug, stdout, "blake3-1024:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  ha_evp_hasher_delete(hasher);

#ifdef DIGEST_IN_HEAP
  free(digest);
#endif

  return;
}

void e2e_2()
{
  if (!input_len) input_len = strlen(input);

  size_t digest_maxsize = 1024;

#ifdef DIGEST_IN_HEAP
  uint8_t *digest = malloc(digest_maxsize);
#else
  uint8_t digest[digest_maxsize];
#endif

  ha_evp_phasher_t hasher = ha_evp_hasher_new();

  {
    ha_evp_hasher_init(hasher, HA_EVPTY_MD5, HA_MD5_DIGEST_SIZE);
    ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
    const char *expected_hash = "5d41402abc4b2a76b9719d911017c592";
    assert(ha_cmphashstr(digest, expected_hash, HA_MD5_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "md5:          passed\n");
    ha_evp_hasher_cleanup(hasher);
  }

  {
    ha_evp_hasher_init(hasher, HA_EVPTY_SHA1, HA_SHA1_DIGEST_SIZE);
    ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
    const char *expected_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    assert(ha_cmphashstr(digest, expected_hash, HA_SHA1_DIGEST_SIZE) == 0);
    __fprintf(debug, stdout, "sha1:         passed\n");
    ha_evp_hasher_cleanup(hasher);
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_224_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_224_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-224:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_256_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982"
          "4";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_256_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-256:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_384_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa9"
          "0125a3c79f90397bdf5f6a13de828684f";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_384_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-384:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA2, HA_SHA2_512_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca"
          "72"
          "323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec04"
          "3";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA2_512_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha2-512:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_224_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_224_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-224:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_256_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f39"
          "2";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_256_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-256:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_384_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1"
          "33"
          "0ff07c0fddee54699a4c3ee0ee9d887";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_384_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-384:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_SHA3, HA_SHA3_512_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6d"
          "f8"
          "91d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a8497"
          "6";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_512_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "sha3-512:     passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_224_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "45524ec454bcc7d4b8f74350c4a4e62809fcb49bc29df62e61b69fa4";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_224_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-224:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_256_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac"
          "8";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_256_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-256:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_384_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb"
          "4c"
          "d8e9c703b8f43e7277b59a5cd402175";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_384_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-384:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_KECCAK, HA_SHA3_512_DIGEST_SIZE);
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39"
          "d4"
          "7de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f97"
          "6";
      assert(ha_cmphashstr(digest, expected_hash,
                           HA_SHA3_512_DIGEST_SIZE) == 0);
      __fprintf(debug, stdout, "keccak-512:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2S, ha_bB(128));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash = "96d539653dbf841c384b53d5f04658e5";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(128)) == 0);
      __fprintf(debug, stdout, "blake2s-128:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2S, ha_bB(160));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "0fee8bbc1b2b15579499fec667487059abd72794";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(160)) == 0);
      __fprintf(debug, stdout, "blake2s-160:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2S, ha_bB(256));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca2"
          "5";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(256)) == 0);
      __fprintf(debug, stdout, "blake2s-256:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(128));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash = "46fb7408d4f285228f4af516ea25851b";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(128)) == 0);
      __fprintf(debug, stdout, "blake2b-128:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(160));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "b5531c7037f06c9f2947132a6a77202c308e8939";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(160)) == 0);
      __fprintf(debug, stdout, "blake2b-160:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(256));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72c"
          "f";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(256)) == 0);
      __fprintf(debug, stdout, "blake2b-256:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE2B, ha_bB(512));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a"
          "65"
          "ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c9"
          "4";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(512)) == 0);
      __fprintf(debug, stdout, "blake2b-512:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  {
    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(224));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c562";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(224)) == 0);
      __fprintf(debug, stdout, "blake3-224:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(256));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "f";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(256)) == 0);
      __fprintf(debug, stdout, "blake3-256:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(384));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "fe"
          "992405f0d785b599a2e3387f6d34d01";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(384)) == 0);
      __fprintf(debug, stdout, "blake3-384:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(512));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "fe"
          "992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338"
          "c";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(512)) == 0);
      __fprintf(debug, stdout, "blake3-512:   passed\n");
      ha_evp_hasher_cleanup(hasher);
    }

    {
      ha_evp_hasher_init(hasher, HA_EVPTY_BLAKE3, ha_bB(1024));
      ha_evp_digest(hasher, (ha_inbuf_t)input, input_len, digest);
      const char *expected_hash =
          "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200"
          "fe"
          "992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338c"
          "c6"
          "8876568ab5c6e524abbcfe881e5b4e1ac9336f3f932d412248c9829536699f0"
          "7a"
          "1b1ce35ffdfe0be5d00c083a8dfd29c9a4303d1374cd70e6abcec6e6b796c";
      assert(ha_cmphashstr(digest, expected_hash, ha_bB(1024)) == 0);
      __fprintf(debug, stdout, "blake3-1024:  passed\n");
      ha_evp_hasher_cleanup(hasher);
    }
  }

  ha_evp_hasher_delete(hasher);

#ifdef DIGEST_IN_HEAP
  free(digest);
#endif

  return;
}

void rune2e()
{
  __fprintf(debug, stdout, "\n == hash\n");
  e2e_0();
  __fprintf(debug, stdout, "\n == evp [  ha_evp_hash]:\n");
  e2e_1();
  __fprintf(debug, stdout, "\n == evp [ha_evp_digest]:\n");
  e2e_2();
  __fprintf(debug, stdout, "\n");
}

int e2e(int argc, char **argv)
{
  struct option long_options[] = {
      {"verbose", no_argument, NULL, 'v'},
      {     NULL,           0, NULL,   0}
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "v", long_options, NULL)) != -1)
  {
    switch (opt)
    {
      case 'v':
        debug = 1;
        break;
      case '?':
        ha_throw(1, 1, ha_curpos, "usage", "%s [-v|--verbose]", argv[0]);
        exit(EXIT_FAILURE);
        /* break; // unreachable */
      default:
        break;
    }
  }

  rune2e();
  __fprintf(debug, stdout, "%s: %s\n", "e2e", "all tests passsed");
  return 0;
}
