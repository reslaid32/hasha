#if !defined(LIBHASHA_SHA2_H_LOADED)
#define LIBHASHA_SHA2_H_LOADED

#include "internal/export.h"
#include "internal/bits.h"
#include "internal/std.h"

#include "sha2_k.h"

#define SHA2_224_BLOCK_SIZE 64
// #define SHA2_224_DIGEST_SIZE 28
#define SHA2_224_DIGEST_SIZE HASHA_bB(224)

#define SHA2_256_BLOCK_SIZE 64
// #define SHA2_256_DIGEST_SIZE 32
#define SHA2_256_DIGEST_SIZE HASHA_bB(256)

#define SHA2_384_BLOCK_SIZE 128
// #define SHA2_384_DIGEST_SIZE 48
#define SHA2_384_DIGEST_SIZE HASHA_bB(384)

#define SHA2_512_BLOCK_SIZE 128
// #define SHA2_512_DIGEST_SIZE 64
#define SHA2_512_DIGEST_SIZE HASHA_bB(512)

#define SHA2_512_224_BLOCK_SIZE 128
// #define SHA2_512_224_DIGEST_SIZE 28
#define SHA2_512_224_DIGEST_SIZE HASHA_bB(224)

#define SHA2_512_256_BLOCK_SIZE 128
// #define SHA2_512_256_DIGEST_SIZE 32
#define SHA2_512_256_DIGEST_SIZE HASHA_bB(256)

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

HASHA_PUBLIC_FUNC void sha2_224_transform(sha2_224_context *ctx, const uint8_t *block);
HASHA_PUBLIC_FUNC void sha2_224_init(sha2_224_context *ctx);
HASHA_PUBLIC_FUNC void sha2_224_update(sha2_224_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha2_224_finalize(sha2_224_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha2_224(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void sha2_256_transform(sha2_256_context *ctx, const uint8_t *block);
HASHA_PUBLIC_FUNC void sha2_256_init(sha2_256_context *ctx);
HASHA_PUBLIC_FUNC void sha2_256_update(sha2_256_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha2_256_finalize(sha2_256_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha2_256(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void sha2_384_transform(sha2_384_context *ctx, const uint8_t *block);
HASHA_PUBLIC_FUNC void sha2_384_init(sha2_384_context *ctx);
HASHA_PUBLIC_FUNC void sha2_384_update(sha2_384_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha2_384_finalize(sha2_384_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha2_384(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void sha2_512_transform(sha2_512_context *ctx, const uint8_t *block);
HASHA_PUBLIC_FUNC void sha2_512_init(sha2_512_context *ctx);
HASHA_PUBLIC_FUNC void sha2_512_update(sha2_512_context *ctx, const uint8_t *data, size_t len);
HASHA_PUBLIC_FUNC void sha2_512_finalize(sha2_512_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha2_512(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void sha2_512_224_transform(sha2_512_224_context *ctx, const uint8_t *block);
HASHA_PUBLIC_FUNC void sha2_512_224_init(sha2_512_224_context *ctx);
HASHA_PUBLIC_FUNC void sha2_512_224_update(sha2_512_224_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha2_512_224_finalize(sha2_512_224_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha2_512_224(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void sha2_512_256_transform(sha2_512_256_context *ctx, const uint8_t *block);
HASHA_PUBLIC_FUNC void sha2_512_256_init(sha2_512_256_context *ctx);
HASHA_PUBLIC_FUNC void sha2_512_256_update(sha2_512_256_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha2_512_256_finalize(sha2_512_256_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha2_512_256(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXTERN_C_END

#endif // LIBHASHA_SHA2_H_LOADED
