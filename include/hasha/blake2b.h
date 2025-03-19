/**
 * @file hasha/blake2b.h
 * @brief Header file for the BLAKE2b hashing algorithm.
 *
 * This file provides the interface for the BLAKE2b cryptographic hash
 * function. It includes the definition of the hash state context and
 * function declarations for initializing, updating, finalizing, and
 * computing the hash in a one-shot operation. BLAKE2b is optimized
 * for 64-bit platforms and offers high security and performance.
 */

#if !defined(LIBHASHA_BLAKE2B_H_LOADED)
#define LIBHASHA_BLAKE2B_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

/** @def BLAKE2B_BLOCK_SIZE
 *  @brief The size of a BLAKE2B block in bytes.
 */
#define BLAKE2B_BLOCK_SIZE 128

/** @def BLAKE2B_DIGEST_SIZE
 *  @brief The default output digest size for BLAKE2B (512 bits).
 */
#define BLAKE2B_DIGEST_SIZE HASHA_bB(512)

HASHA_EXTERN_C_BEG

/**
 * @struct ha_blake2b_context
 * @brief BLAKE2B hashing context structure.
 *
 * This structure maintains the state of the BLAKE2B hashing process.
 */
typedef struct ha_blake2b_context
{
  uint64_t h[8];                   /**< Internal hash state. */
  uint64_t t[2];                   /**< Message counter. */
  uint64_t f[2];                   /**< Finalization flags. */
  uint8_t buf[BLAKE2B_BLOCK_SIZE]; /**< Data buffer. */
  size_t buflen; /**< Number of bytes currently in the buffer. */
  size_t outlen; /**< Length of the hash output. */
} ha_blake2b_context;

/**
 * @brief Initializes a BLAKE2B context.
 *
 * @param ctx Pointer to the BLAKE2B context to initialize.
 * @param outlen Desired length of the output hash (1 to 64 bytes).
 */
HASHA_PUBLIC_FUNC void ha_blake2b_init(ha_blake2b_context *ctx,
                                       size_t outlen);

/**
 * @brief Updates the BLAKE2B hash state with input data.
 *
 * @param ctx Pointer to the initialized BLAKE2B context.
 * @param data Pointer to the input data.
 * @param len Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void ha_blake2b_update(ha_blake2b_context *ctx,
                                         const uint8_t *data, size_t len);

/**
 * @brief Finalizes the BLAKE2B hash and produces the digest.
 *
 * @param ctx Pointer to the initialized BLAKE2B context.
 * @param digest Pointer to the output buffer where the hash will be
 * stored.
 */
HASHA_PUBLIC_FUNC void ha_blake2b_final(ha_blake2b_context *ctx,
                                        uint8_t *digest);

/**
 * @brief Computes the BLAKE2B hash in a one-shot operation.
 *
 * This function initializes a BLAKE2B context, processes the input data,
 * and finalizes the hash computation, storing the result in the provided
 * buffer.
 *
 * @param data Pointer to the input data.
 * @param len Length of the input data in bytes.
 * @param digest Pointer to the output buffer where the hash will be
 * stored.
 * @param digestlen Desired length of the output hash (1 to 64 bytes).
 */
HASHA_PUBLIC_FUNC void ha_blake2b_hash(const uint8_t *data, size_t len,
                                       uint8_t *digest, size_t digestlen);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_BLAKE2B_H_LOADED
