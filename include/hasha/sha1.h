/**
 * @file hasha/sha1.h
 * @brief Header file for the SHA-1 cryptographic hash algorithm.
 *
 * This header file defines the interface for the SHA-1 hash function,
 * including the context structure, constants, and function declarations
 * required for computing a SHA-1 hash. SHA-1 is a widely-used
 * cryptographic hash function that produces a 160-bit (20-byte) hash
 * value, and is commonly used for data integrity verification.
 *
 * The functions provided in this file allow for incremental hashing via
 * context initialization, data updating, and finalization, as well as a
 * one-shot function for computing the hash of an entire input in a single
 * call.
 *
 * @note SHA-1 is considered weak for modern cryptographic applications and
 * should be used only in legacy systems or non-critical applications.
 *
 * @see https://en.wikipedia.org/wiki/SHA-1 for further information on
 * SHA-1.
 */

#if !defined(LIBHASHA_SHA1_H_LOADED)
#define LIBHASHA_SHA1_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

/**
 * @def SHA1_BLOCK_SIZE
 * @brief The block size used in SHA-1 (in bytes).
 */
#define SHA1_BLOCK_SIZE 64

/**
 * @def SHA1_DIGEST_SIZE
 * @brief The size of the SHA-1 hash output (in bytes).
 */
#define SHA1_DIGEST_SIZE HASHA_bB(160)

HASHA_EXTERN_C_BEG

/**
 * @struct sha1_context
 * @brief SHA-1 context structure used to store the internal state during
 * hashing.
 *
 * This structure holds the state of the SHA-1 hash calculation, including
 * the intermediate state variables, bit count, and buffer used to store
 * input data.
 */
typedef struct sha1_context
{
  uint32_t state[5];  /**< The SHA-1 state variables (5 words). */
  uint64_t bit_count; /**< The number of processed bits. */
  uint8_t buffer[SHA1_BLOCK_SIZE]; /**< The buffer to hold the current
                                      input block. */
} sha1_context;

/**
 * @brief SHA-1 constant K values used in the transformation function.
 */
static const uint32_t SHA1_K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
                                   0xCA62C1D6};

/**
 * @brief SHA-1 initial hash values.
 */
static const uint32_t SHA1_H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                    0x10325476, 0xC3D2E1F0};

/**
 * @brief Performs the SHA-1 transformation step on a 512-bit data block.
 *
 * This function processes the given data block and updates the internal
 * state of the SHA-1 context with the result.
 *
 * @param ctx Pointer to the SHA-1 context structure.
 * @param block Pointer to the 512-bit (64-byte) input data block.
 */
HASHA_PUBLIC_FUNC void sha1_transform(sha1_context *ctx,
                                      const uint8_t *block);

/**
 * @brief Initializes the SHA-1 context for a new hash computation.
 *
 * This function initializes the SHA-1 context to its starting state with
 * the default initial hash values (SHA1_H0) and prepares the context for
 * the hashing process.
 *
 * @param ctx Pointer to the SHA-1 context structure.
 */
HASHA_PUBLIC_FUNC void sha1_init(sha1_context *ctx);

/**
 * @brief Updates the SHA-1 context with new data.
 *
 * This function updates the SHA-1 context with a portion of the input
 * data. It processes the input data in 512-bit blocks and handles the
 * internal state updates.
 *
 * @param ctx Pointer to the SHA-1 context structure.
 * @param data Pointer to the input data.
 * @param len The length of the input data.
 */
HASHA_PUBLIC_FUNC void sha1_update(sha1_context *ctx, const uint8_t *data,
                                   size_t len);

/**
 * @brief Finalizes the SHA-1 context and produces the resulting hash
 * digest.
 *
 * This function finalizes the hash computation, pads the data if
 * necessary, and produces the final 160-bit (20-byte) hash digest in the
 * provided output buffer.
 *
 * @param ctx Pointer to the SHA-1 context structure.
 * @param digest Pointer to the output buffer where the 160-bit hash digest
 * will be stored.
 */
HASHA_PUBLIC_FUNC void sha1_finalize(sha1_context *ctx, uint8_t *digest);

/**
 * @brief Computes the SHA-1 hash for the given input data in one-shot
 * mode.
 *
 * This function computes the SHA-1 hash for the entire input data in a
 * single call, without requiring separate initialization, update, or
 * finalize steps.
 *
 * @param data Pointer to the input data.
 * @param len The length of the input data.
 * @param digest Pointer to the output buffer where the 160-bit hash digest
 * will be stored.
 */
HASHA_PUBLIC_FUNC void sha1_oneshot(const uint8_t *data, size_t len,
                                    uint8_t *digest);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_SHA1_H_LOADED
