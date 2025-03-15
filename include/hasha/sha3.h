#if !defined(LIBHASHA_SHA3_H_LOADED)
#define LIBHASHA_SHA3_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"
#include "keccak1600.h"

#define KECCAK_ROUNDS 24

#define SHA3_224_RATE 144
// #define SHA3_224_DIGEST_SIZE 28
#define SHA3_224_DIGEST_SIZE HASHA_bB(224)

#define SHA3_256_RATE 136
// #define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_DIGEST_SIZE HASHA_bB(256)

#define SHA3_384_RATE 104
// #define SHA3_384_DIGEST_SIZE 48
#define SHA3_384_DIGEST_SIZE HASHA_bB(384)

#define SHA3_512_RATE 72
// #define SHA3_512_DIGEST_SIZE 64
#define SHA3_512_DIGEST_SIZE HASHA_bB(512)

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT
{
  uint8_t state[200];
  size_t rate;
  size_t capacity;
  size_t absorb_index;
  size_t squeeze_index;
} sha3_context;

typedef sha3_context sha3_224_context, sha3_256_context, sha3_384_context,
    sha3_512_context;

HASHA_PUBLIC_FUNC void sha3_224_init(sha3_224_context *ctx);
HASHA_PUBLIC_FUNC void sha3_224_absorb(sha3_224_context *ctx,
                                       const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha3_224_finalize(sha3_224_context *ctx);
HASHA_PUBLIC_FUNC void sha3_224_squeeze(sha3_224_context *ctx,
                                        uint8_t *digest);
HASHA_PUBLIC_FUNC void sha3_224_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

HASHA_PUBLIC_FUNC void sha3_256_init(sha3_256_context *ctx);
HASHA_PUBLIC_FUNC void sha3_256_absorb(sha3_256_context *ctx,
                                       const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha3_256_finalize(sha3_256_context *ctx);
HASHA_PUBLIC_FUNC void sha3_256_squeeze(sha3_256_context *ctx,
                                        uint8_t *digest);
HASHA_PUBLIC_FUNC void sha3_256_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

HASHA_PUBLIC_FUNC void sha3_384_init(sha3_384_context *ctx);
HASHA_PUBLIC_FUNC void sha3_384_absorb(sha3_384_context *ctx,
                                       const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha3_384_finalize(sha3_384_context *ctx);
HASHA_PUBLIC_FUNC void sha3_384_squeeze(sha3_384_context *ctx,
                                        uint8_t *digest);
HASHA_PUBLIC_FUNC void sha3_384_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

HASHA_PUBLIC_FUNC void sha3_512_init(sha3_512_context *ctx);
HASHA_PUBLIC_FUNC void sha3_512_absorb(sha3_512_context *ctx,
                                       const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void sha3_512_finalize(sha3_512_context *ctx);
HASHA_PUBLIC_FUNC void sha3_512_squeeze(sha3_512_context *ctx,
                                        uint8_t *digest);
HASHA_PUBLIC_FUNC void sha3_512_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_SHA3_H_LOADED
