#if !defined(LIBHASHA_SHA1_H_LOADED)
#define LIBHASHA_SHA1_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

#define SHA1_BLOCK_SIZE 64
// #define SHA1_DIGEST_SIZE 20
#define SHA1_DIGEST_SIZE HASHA_bB(160)

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT
{
  uint32_t state[5];
  uint64_t bit_count;
  uint8_t buffer[SHA1_BLOCK_SIZE];
} sha1_context;

static const uint32_t SHA1_K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
                                   0xCA62C1D6};

static const uint32_t SHA1_H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                    0x10325476, 0xC3D2E1F0};

HASHA_PUBLIC_FUNC void sha1_transform(sha1_context *ctx,
                                      const uint8_t *block);
HASHA_PUBLIC_FUNC void sha1_init(sha1_context *ctx);
HASHA_PUBLIC_FUNC void sha1_update(sha1_context *ctx, const uint8_t *data,
                                   size_t len);
HASHA_PUBLIC_FUNC void sha1_finalize(sha1_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void sha1_oneshot(const uint8_t *data, size_t len,
                                    uint8_t *digest);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_SHA1_H_LOADED
