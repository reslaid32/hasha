#if !defined(LIBHASHA_MD5_H_LOADED)
#define LIBHASHA_MD5_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

/**
 * @def MD5_BLOCK_SIZE
 * @brief Block size (in bytes) for the MD5 algorithm.
 */
#define MD5_BLOCK_SIZE 64

/**
 * @def MD5_DIGEST_SIZE
 * @brief Digest size (in bytes) for the MD5 algorithm (128 bits).
 */
#define MD5_DIGEST_SIZE HASHA_bB(128)

HASHA_EXTERN_C_BEG

/**
 * @struct md5_context
 * @brief Context structure for MD5 hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the MD5 hash computation.
 */
typedef struct HASHA_EXPORT
{
  uint32_t state[4]; /**< Current MD5 state (4 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[MD5_BLOCK_SIZE]; /**< Buffer used for processing input
                                     data in 512-bit blocks. */
} md5_context;

/**
 * @brief Initializes the MD5 context.
 *
 * This function initializes the MD5 context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the MD5 context structure to initialize.
 */
HASHA_PUBLIC_FUNC void md5_init(md5_context *ctx);

/**
 * @brief Updates the MD5 context with new data.
 *
 * This function processes the provided data and updates the MD5 context
 * state.
 *
 * @param ctx Pointer to the MD5 context structure.
 * @param data Pointer to the input data to process.
 * @param len Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void md5_update(md5_context *ctx, const uint8_t *data,
                                  size_t len);

/**
 * @brief Finalizes the MD5 computation and produces the hash digest.
 *
 * This function finalizes the MD5 hash calculation and outputs the
 * resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the MD5 context structure.
 * @param digest Pointer to the output buffer to store the final MD5 digest
 * (16 bytes).
 */
HASHA_PUBLIC_FUNC void md5_finalize(md5_context *ctx, uint8_t *digest);

/**
 * @brief Computes the MD5 hash in a one-shot operation.
 *
 * This function computes the MD5 hash of the provided data in a single
 * call. It initializes, updates, and finalizes the MD5 computation
 * internally.
 *
 * @param data Pointer to the input data to process.
 * @param len Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final MD5 digest
 * (16 bytes).
 */
HASHA_PUBLIC_FUNC void md5_oneshot(const uint8_t *data, size_t len,
                                   uint8_t *digest);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_MD5_H_LOADED
