/**
 * @file hasha/blake2s.h
 * @brief Header file for the BLAKE2s hashing algorithm.
 *
 * This file provides the interface for the BLAKE2s cryptographic hash
 * function, including the definition of the hash state context and
 * function declarations for initializing, updating, finalizing, and
 * computing the hash in a one-shot operation.
 */

#if !defined(__HASHA_BLAKE2S_H)
#define __HASHA_BLAKE2S_H

#include "internal/internal.h"

#define HA_BLAKE2S_BLOCK_SIZE  64
#define HA_BLAKE2S_DIGEST_SIZE ha_bB(256)

HA_EXTERN_C_BEG

/**
 * @struct ha_blake2s_context
 * @brief BLAKE2s hashing context structure.
 *
 * This structure holds the internal state of the BLAKE2s hash computation.
 */
typedef struct ha_blake2s_context
{
  uint32_t h[8];                  /**< Internal hash state. */
  uint32_t t[2];                  /**< Message counter. */
  uint32_t f[2];                  /**< Finalization flags. */
  uint8_t
      buf[HA_BLAKE2S_BLOCK_SIZE]; /**< Buffer for partial input blocks. */
  size_t buflen; /**< Number of bytes currently in the buffer. */
  size_t outlen; /**< Desired output length of the hash. */
} ha_blake2s_context;

/**
 * @brief Initializes the BLAKE2s hashing context.
 *
 * @param ctx Pointer to the BLAKE2s context.
 */
HA_PUBFUN void ha_blake2s_init(ha_blake2s_context *ctx);

/**
 * @brief Updates the BLAKE2s hash with input data.
 *
 * This function processes the input data in blocks, updating the internal
 * state.
 *
 * @param ctx Pointer to the BLAKE2s context.
 * @param data Pointer to the input data.
 * @param len Length of the input data in bytes.
 */
HA_PUBFUN void ha_blake2s_update(ha_blake2s_context *ctx, ha_inbuf_t data,
                                 size_t len);

/**
 * @brief Finalizes the BLAKE2s hash computation.
 *
 * This function finalizes the hash and writes the output to the provided
 * buffer.
 *
 * @param ctx Pointer to the BLAKE2s context.
 * @param digest Pointer to the output buffer (must be at least `outlen`
 * bytes).
 * @param digestlen Desired length of the hash output in bytes (1–32).
 */
HA_PUBFUN void ha_blake2s_final(ha_blake2s_context *ctx,
                                ha_digest_t digest, size_t digestlen);

/**
 * @brief Computes the BLAKE2s hash of the input data.
 *
 * This function performs a one-shot hash computation, initializing,
 * updating, and finalizing the context in a single call.
 *
 * @param data Pointer to the input data.
 * @param len Length of the input data in bytes.
 * @param digest Pointer to the output buffer (must be at least `digestlen`
 * bytes).
 * @param digestlen Desired length of the hash output in bytes (1–32).
 */
HA_PUBFUN void ha_blake2s_hash(ha_inbuf_t data, size_t len,
                               ha_digest_t digest, size_t digestlen);

HA_EXTERN_C_END

#endif  // __HASHA_BLAKE2S_H
