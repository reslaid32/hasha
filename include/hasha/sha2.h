#if !defined(LIBHASHA_SHA2_H_LOADED)
#define LIBHASHA_SHA2_H_LOADED

#include "export.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define SHA2_224_BLOCK_SIZE 64
#define SHA2_224_DIGEST_SIZE 28

#define SHA2_256_BLOCK_SIZE 64
#define SHA2_256_DIGEST_SIZE 32

#define SHA2_384_BLOCK_SIZE 128
#define SHA2_384_DIGEST_SIZE 48

#define SHA2_512_BLOCK_SIZE 128
#define SHA2_512_DIGEST_SIZE 64

#define SHA2_512_224_BLOCK_SIZE 128
#define SHA2_512_224_DIGEST_SIZE 28

#define SHA2_512_256_BLOCK_SIZE 128
#define SHA2_512_256_DIGEST_SIZE 32

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[SHA2_224_BLOCK_SIZE];
} sha2_224_context;

typedef struct HASHA_EXPORT {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[SHA2_256_BLOCK_SIZE];
} sha2_256_context;

typedef struct HASHA_EXPORT {
    uint64_t state[8];
    uint64_t bit_count[2];
    uint8_t buffer[SHA2_384_BLOCK_SIZE];
} sha2_384_context;

typedef struct HASHA_EXPORT {
    uint64_t state[8];
    uint64_t bit_count;
    uint8_t buffer[SHA2_512_BLOCK_SIZE];
} sha2_512_context;

typedef struct HASHA_EXPORT {
    uint64_t state[8];
    uint64_t bit_count;
    uint8_t buffer[SHA2_512_224_BLOCK_SIZE];
} sha2_512_224_context;

typedef struct HASHA_EXPORT {
    uint64_t state[8];
    uint64_t bit_count;
    uint8_t buffer[SHA2_512_256_BLOCK_SIZE];
} sha2_512_256_context;

static const uint32_t SHA2_256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t SHA2_512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const uint32_t SHA2_224_H0[8] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const uint32_t SHA2_256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint64_t SHA2_384_H0[8] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

static const uint64_t SHA2_512_H0[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const uint64_t SHA2_512_224_H0[8] = {
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942,
    0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
};

static const uint64_t SHA2_512_256_H0[8] = {
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
    0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
};

HASHA_EXPORT HASHA_INLINE void sha2_224_transform(sha2_224_context *ctx, const uint8_t *block);
HASHA_EXPORT HASHA_INLINE void sha2_224_init(sha2_224_context *ctx);
HASHA_EXPORT HASHA_INLINE void sha2_224_update(sha2_224_context *ctx, const uint8_t *data, size_t length);
HASHA_EXPORT HASHA_INLINE void sha2_224_finalize(sha2_224_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void sha2_224(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXPORT HASHA_INLINE void sha2_256_transform(sha2_256_context *ctx, const uint8_t *block);
HASHA_EXPORT HASHA_INLINE void sha2_256_init(sha2_256_context *ctx);
HASHA_EXPORT HASHA_INLINE void sha2_256_update(sha2_256_context *ctx, const uint8_t *data, size_t length);
HASHA_EXPORT HASHA_INLINE void sha2_256_finalize(sha2_256_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void sha2_256(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXPORT HASHA_INLINE void sha2_384_transform(sha2_384_context *ctx, const uint8_t *block);
HASHA_EXPORT HASHA_INLINE void sha2_384_init(sha2_384_context *ctx);
HASHA_EXPORT HASHA_INLINE void sha2_384_update(sha2_384_context *ctx, const uint8_t *data, size_t length);
HASHA_EXPORT HASHA_INLINE void sha2_384_finalize(sha2_384_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void sha2_384(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXPORT HASHA_INLINE void sha2_512_transform(sha2_512_context *ctx, const uint8_t *block);
HASHA_EXPORT HASHA_INLINE void sha2_512_init(sha2_512_context *ctx);
HASHA_EXPORT HASHA_INLINE void sha2_512_update(sha2_512_context *ctx, const uint8_t *data, size_t len);
HASHA_EXPORT HASHA_INLINE void sha2_512_finalize(sha2_512_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void sha2_512(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXPORT HASHA_INLINE void sha2_512_224_transform(sha2_512_224_context *ctx, const uint8_t *block);
HASHA_EXPORT HASHA_INLINE void sha2_512_224_init(sha2_512_224_context *ctx);
HASHA_EXPORT HASHA_INLINE void sha2_512_224_update(sha2_512_224_context *ctx, const uint8_t *data, size_t length);
HASHA_EXPORT HASHA_INLINE void sha2_512_224_finalize(sha2_512_224_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void sha2_512_224(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXPORT HASHA_INLINE void sha2_512_256_transform(sha2_512_256_context *ctx, const uint8_t *block);
HASHA_EXPORT HASHA_INLINE void sha2_512_256_init(sha2_512_256_context *ctx);
HASHA_EXPORT HASHA_INLINE void sha2_512_256_update(sha2_512_256_context *ctx, const uint8_t *data, size_t length);
HASHA_EXPORT HASHA_INLINE void sha2_512_256_finalize(sha2_512_256_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void sha2_512_256(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXTERN_C_END

#endif // LIBHASHA_SHA2_H_LOADED
