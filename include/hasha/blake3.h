#if !defined(LIBHASHA_BLAKE3_H_LOADED)
#define LIBHASHA_BLAKE3_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT
{
  uint8_t input[64];
  uint32_t bytes;
  uint32_t block;
  uint64_t chunk;
  uint32_t *cv, cv_buf[54 * 8];
} blake3_context;

HASHA_PUBLIC_FUNC void blake3_init(blake3_context *ctx);
HASHA_PUBLIC_FUNC void blake3_update(blake3_context *ctx,
                                     const uint8_t *data, size_t length);
HASHA_PUBLIC_FUNC void blake3_final(blake3_context *ctx, uint8_t *digest,
                                    size_t length);
HASHA_PUBLIC_FUNC void blake3_oneshot(const uint8_t *data, size_t length,
                                      uint8_t *digest,
                                      size_t digest_length);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_BLAKE3_H_LOADED
