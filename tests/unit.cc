
#include "../include/hasha/pp/pp.hpp"

#include <string.h>
#include <stdio.h>
#include <assert.h>

void print_hash(const uint8_t *hash, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int compare_hash(const uint8_t *hash, const char *expected_hash, size_t hash_len) {
    char hash_str[hash_len * 2 + 1];
    for (size_t i = 0; i < hash_len; ++i) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[hash_len * 2] = '\0';

    return strcmp(hash_str, expected_hash);
}

void rununit() {
    std::string input = "hello";
    std::vector<uint8_t> digest;

    {
        uint32_t crc;
        hasha::crc::oneshot(input, crc);

        uint32_t expected_hash = 0x3610a686;

        assert(crc == expected_hash);
        printf("CRC:          Passed\n");
    }
    {
        hasha::md5::oneshot(input, digest);

        const char *expected_hash = "5d41402abc4b2a76b9719d911017c592";

        assert(hasha::digest::compare(expected_hash, digest) == 0);

        printf("MD5:          Passed\n");
    }
    {
        hasha::sha1::oneshot(input, digest);

        const char *expected_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

        assert(hasha::digest::compare(expected_hash, digest) == 0);

        printf("SHA1:         Passed\n");
    }
    {
        hasha::sha2::sha224::oneshot(input, digest);

        const char *expected_hash = "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193";

        assert(hasha::digest::compare(expected_hash, digest) == 0);

        printf("SHA2-224:     Passed\n");
    }
    {
        hasha::sha2::sha256::oneshot(input, digest);
        
        const char *expected_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA2-256:     Passed\n");
    }
    {
        hasha::sha2::sha384::oneshot(input, digest);

        const char *expected_hash = "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA2-384:     Passed\n");
    }
    {
        hasha::sha2::sha512::oneshot(input, digest);

        const char *expected_hash = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA2-512:     Passed\n");
    }
    {
        hasha::sha2::sha512_224::oneshot(input, digest);

        const char *expected_hash = "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA2-512/224: Passed\n");
    }
    {
        hasha::sha2::sha512_256::oneshot(input, digest);

        const char *expected_hash = "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA2-512/256: Passed\n");
    }

    {
        hasha::sha3::sha3_224::oneshot(input, digest);

        const char *expected_hash = "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA3-224:     Passed\n");
    }
    {
        hasha::sha3::sha3_256::oneshot(input, digest);
        
        const char *expected_hash = "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA3-256:     Passed\n");
    }
    {
        hasha::sha3::sha3_384::oneshot(input, digest);

        const char *expected_hash = "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA3-384:     Passed\n");
    }
    {
        hasha::sha3::sha3_512::oneshot(input, digest);

        const char *expected_hash = "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("SHA3-512:     Passed\n");
    }
    {
        hasha::keccak::keccak224::oneshot(input, digest);

        const char *expected_hash = "45524ec454bcc7d4b8f74350c4a4e62809fcb49bc29df62e61b69fa4";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("KECCAK-224:   Passed\n");
    }
    {
        hasha::keccak::keccak256::oneshot(input, digest);

        const char *expected_hash = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("KECCAK-256:   Passed\n");
    }
    {
        hasha::keccak::keccak384::oneshot(input, digest);

        const char *expected_hash = "dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb4cd8e9c703b8f43e7277b59a5cd402175";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("KECCAK-384:   Passed\n");
    }
    {
        hasha::keccak::keccak512::oneshot(input, digest);

        const char *expected_hash = "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976";

        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("KECCAK-512:   Passed\n");
    }
    {
        hasha::blake3::oneshot(input, digest, hasha::bytes(224));

        const char *expected_hash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c562";
        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("BLAKE3-224:   Passed\n");
    }
    {
        hasha::blake3::oneshot(input, digest, hasha::bytes(256));

        const char *expected_hash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("BLAKE3-256:   Passed\n");
    }
    {
        hasha::blake3::oneshot(input, digest, hasha::bytes(384));

        const char *expected_hash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01";
        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("BLAKE3-384:   Passed\n");
    }
    {
        hasha::blake3::oneshot(input, digest, hasha::bytes(512));

        const char *expected_hash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338c";
        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("BLAKE3-512:   Passed\n");
    }
    {
        hasha::blake3::oneshot(input, digest, hasha::bytes(1024));

        const char *expected_hash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200fe992405f0d785b599a2e3387f6d34d01faccfeb22fb697ef3fd53541241a338cc68876568ab5c6e524abbcfe881e5b4e1ac9336f3f932d412248c9829536699f07a1b1ce35ffdfe0be5d00c083a8dfd29c9a4303d1374cd70e6abcec6e6b796c";
        assert(hasha::digest::compare(expected_hash, digest) == 0);
        printf("BLAKE3-1024:  Passed\n");
    }
}

int main(void) {
    rununit();
    printf("[ALL TESTS]   PASSED!\n");
    return 0;
}