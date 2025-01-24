#if !defined(LIBHASHA_MD5_H_LOADED)
#define LIBHASHA_MD5_H_LOADED

#include "export.h"

#include <stdint.h>
#include <stddef.h>

#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

HASHA_EXTERN_C_BEG

typedef struct {
    uint32_t state[4];
    uint64_t bit_count;
    uint8_t buffer[MD5_BLOCK_SIZE];
} md5_context;

HASHA_EXPORT HASHA_INLINE void md5_init(md5_context *ctx);
HASHA_EXPORT HASHA_INLINE void md5_update(md5_context *ctx, const uint8_t *data, size_t len);
HASHA_EXPORT HASHA_INLINE void md5_finalize(md5_context *ctx, uint8_t *digest);
HASHA_EXPORT HASHA_INLINE void md5(const uint8_t *data, size_t len, uint8_t *digest);

HASHA_EXTERN_C_END

#endif // LIBHASHA_MD5_H_LOADED
