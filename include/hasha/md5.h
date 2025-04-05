/**
 * @file hasha/md5.h
 * @brief Header file for the MD5 cryptographic hash function.
 *
 * This header file defines the interface for computing the MD5 hash, a
 * widely-used cryptographic hash algorithm that produces a 128-bit
 * (16-byte) digest. The MD5 algorithm processes data in 512-bit blocks and
 * is commonly used for checksum calculations and data integrity
 * verification.
 *
 * @note MD5 is considered cryptographically broken and unsuitable for
 * secure applications. It is provided primarily for legacy support and
 * non-critical usage scenarios.
 *
 * @see https://en.wikipedia.org/wiki/MD5 for further details on the MD5
 * algorithm.
 */

#if !defined(__HASHA_MD5_H)
#define __HASHA_MD5_H

#include "internal/internal.h"

/**
 * @def HA_MD5_BLOCK_SIZE
 * @brief Block size (in bytes) for the MD5 algorithm.
 */
#define HA_MD5_BLOCK_SIZE 64

/**
 * @def HA_MD5_DIGEST_SIZE
 * @brief Digest size (in bytes) for the MD5 algorithm (128 bits).
 */
#define HA_MD5_DIGEST_SIZE ha_bB(128)

HA_EXTERN_C_BEG

/**
 * @struct ha_md5_context
 * @brief Context structure for MD5 hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the MD5 hash computation.
 */
typedef struct ha_md5_context
{
  uint32_t state[4]; /**< Current MD5 state (4 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[HA_MD5_BLOCK_SIZE]; /**< Buffer used for processing input
                                     data in 512-bit blocks. */
} ha_md5_context;

/**
 * @brief Initializes the MD5 context.
 *
 * This function initializes the MD5 context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the MD5 context structure to initialize.
 */
HA_PUBFUN void ha_md5_init(ha_md5_context *ctx);

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
HA_PUBFUN void ha_md5_update(ha_md5_context *ctx, ha_inbuf_t data,
                             size_t len);

/**
 * @brief Finalizes the MD5 computation and produces the hash digest.
 *
 * This function finals the MD5 hash calculation and outputs the
 * resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the MD5 context structure.
 * @param digest Pointer to the output buffer to store the final MD5 digest
 * (16 bytes).
 */
HA_PUBFUN void ha_md5_final(ha_md5_context *ctx, ha_digest_t digest);

/**
 * @brief Computes the MD5 hash in a one-shot operation.
 *
 * This function computes the MD5 hash of the provided data in a single
 * call. It initializes, updates, and finals the MD5 computation
 * internally.
 *
 * @param data Pointer to the input data to process.
 * @param len Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final MD5 digest
 * (16 bytes).
 */
HA_PUBFUN void ha_md5_hash(ha_inbuf_t data, size_t len,
                           ha_digest_t digest);

HA_EXTERN_C_END

#endif  // __HASHA_MD5_H
