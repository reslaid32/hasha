#if !defined(LIBHASHA_KECCAK_H_LOADED)
#define LIBHASHA_KECCAK_H_LOADED

#include "export.h"
#include "bits.h"
#include "sha3_keccak.h"

#include "std.h"

#define KECCAK_224_RATE 144
// #define KECCAK_224_DIGEST_SIZE 28
#define KECCAK_224_DIGEST_SIZE HASHA_bB(224)

#define KECCAK_256_RATE 136
// #define KECCAK_256_DIGEST_SIZE 32
#define KECCAK_256_DIGEST_SIZE HASHA_bB(256)

#define KECCAK_384_RATE 104
// #define KECCAK_384_DIGEST_SIZE 48
#define KECCAK_384_DIGEST_SIZE HASHA_bB(384)

#define KECCAK_512_RATE 72
// #define KECCAK_512_DIGEST_SIZE 64
#define KECCAK_512_DIGEST_SIZE HASHA_bB(512)

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT {
    uint8_t state[200];
    size_t rate;
    size_t capacity;
    size_t absorb_index;
    size_t squeeze_index;
} keccak_context;

typedef keccak_context keccak_224_context, keccak_256_context, keccak_384_context, keccak_512_context;

HASHA_PUBLIC_FUNC void keccak_224_init(keccak_224_context *ctx);
HASHA_PUBLIC_FUNC void keccak_224_absorb(keccak_224_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void keccak_224_finalize(keccak_224_context *ctx);
HASHA_PUBLIC_FUNC void keccak_224_squeeze(keccak_224_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void keccak_224(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void keccak_256_init(keccak_256_context *ctx);
HASHA_PUBLIC_FUNC void keccak_256_absorb(keccak_256_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void keccak_256_finalize(keccak_256_context *ctx);
HASHA_PUBLIC_FUNC void keccak_256_squeeze(keccak_256_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void keccak_256(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void keccak_384_init(keccak_384_context *ctx);
HASHA_PUBLIC_FUNC void keccak_384_absorb(keccak_384_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void keccak_384_finalize(keccak_384_context *ctx);
HASHA_PUBLIC_FUNC void keccak_384_squeeze(keccak_384_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void keccak_384(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_PUBLIC_FUNC void keccak_512_init(keccak_512_context *ctx);
HASHA_PUBLIC_FUNC void keccak_512_absorb(keccak_512_context *ctx, const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void keccak_512_finalize(keccak_512_context *ctx);
HASHA_PUBLIC_FUNC void keccak_512_squeeze(keccak_512_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void keccak_512(const uint8_t *data, size_t length, uint8_t *digest);

HASHA_EXTERN_C_END

#endif // LIBHASHA_KECCAK_H_LOADED
