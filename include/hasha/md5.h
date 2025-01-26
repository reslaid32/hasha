#if !defined(LIBHASHA_MD5_H_LOADED)
#define LIBHASHA_MD5_H_LOADED

#include "export.h"
#include "bits.h"
#include "std.h"

#define MD5_BLOCK_SIZE 64
// #define MD5_DIGEST_SIZE 16
#define MD5_DIGEST_SIZE HASHA_bB(128)

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT {
    uint32_t state[4];
    uint64_t bit_count;
    uint8_t buffer[MD5_BLOCK_SIZE];
} md5_context;

HASHA_PUBLIC_FUNC void md5_init(md5_context *ctx);
HASHA_PUBLIC_FUNC void md5_update(md5_context *ctx, const uint8_t *data, size_t len);
HASHA_PUBLIC_FUNC void md5_finalize(md5_context *ctx, uint8_t *digest);
HASHA_PUBLIC_FUNC void md5(const uint8_t *data, size_t len, uint8_t *digest);

HASHA_EXTERN_C_END

#endif // LIBHASHA_MD5_H_LOADED
