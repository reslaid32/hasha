/**
 * @file hasha/blake3.h
 * @brief Header file for the BLAKE3 hashing algorithm.
 *
 * This file provides the interface for the BLAKE3 cryptographic hash
 * function, including the definition of the hash state context and
 * function declarations for initializing, updating, finalizing, and
 * computing the hash in a one-shot operation.
 *
 * The BLAKE3 algorithm is designed for high performance and security,
 * processing data in chunks and producing variable-length digests. This
 * header is part of the libhasha library.
 *
 * @note The implementation assumes that the target system supports the
 * necessary integer types and that sufficient memory is allocated for the
 * digest.
 *
 * @see https://github.com/BLAKE3-team/BLAKE3 for further details on the
 * BLAKE3 algorithm.
 */

#if !defined(LIBHASHA_BLAKE3_H_LOADED)
#define LIBHASHA_BLAKE3_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

HASHA_EXTERN_C_BEG

/**
 * @brief BLAKE3 hash state context.
 *
 * This structure holds the internal state of the BLAKE3 hashing algorithm.
 * It includes buffers for input data, the current hash state, and other
 * necessary variables for processing the data in chunks.
 */
typedef struct
{
  /**
   * @brief Input buffer for storing data being processed.
   *
   * This buffer temporarily holds up to 64 bytes of input data being
   * processed at a time during the hash update operation.
   */
  uint8_t input[64];

  /**
   * @brief The number of bytes processed so far.
   *
   * This counter keeps track of the total number of bytes processed by the
   * hash function so far, including those passed in previous
   * `blake3_update` calls.
   */
  uint32_t bytes;

  /**
   * @brief The block counter for the current chunk.
   *
   * This counter tracks the number of blocks that have been processed
   * within the current chunk of data being hashed.
   */
  uint32_t block;

  /**
   * @brief The chunk counter for tracking progress.
   *
   * This variable tracks the number of chunks that have been processed
   * during the hashing process.
   */
  uint64_t chunk;

  /**
   * @brief Pointer to the current hash state.
   *
   * This is a pointer to the current state of the hash, which is updated
   * during each step of the hashing process. It is a pointer to an array
   * of 32-bit words.
   */
  uint32_t *cv;

  /**
   * @brief Buffer for the hash state (54 * 8 words).
   *
   * This buffer stores the intermediate hash states during the hashing
   * process. It is large enough to hold multiple rounds of hashing state,
   * with each round consisting of 8 words (32 bytes).
   */
  uint32_t cv_buf[54 * 8];
} blake3_context;

/**
 * @brief Initializes the BLAKE3 context for hashing.
 *
 * This function sets up the initial state of the BLAKE3 context by
 * clearing the internal state and preparing it to receive input data.
 *
 * @param ctx Pointer to a BLAKE3 context structure to be initialized.
 */
HASHA_PUBLIC_FUNC void blake3_init(blake3_context *ctx);

/**
 * @brief Updates the BLAKE3 hash with more input data.
 *
 * This function adds additional data to the ongoing hash computation. It
 * can be called multiple times with chunks of data until all data has been
 * processed.
 *
 * @param ctx Pointer to the BLAKE3 context structure.
 * @param data Pointer to the input data to be hashed.
 * @param length The length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void blake3_update(blake3_context *ctx,
                                     const uint8_t *data, size_t length);

/**
 * @brief Finalizes the BLAKE3 hash and produces the final digest.
 *
 * This function finishes the hash computation, producing the final digest
 * from the data that has been passed to `blake3_update`. The length of the
 * resulting digest is specified by the caller.
 *
 * @param ctx Pointer to the BLAKE3 context structure.
 * @param digest Pointer to a buffer where the resulting digest will be
 * stored.
 * @param length The length of the digest to be produced, in bytes.
 */
HASHA_PUBLIC_FUNC void blake3_final(blake3_context *ctx, uint8_t *digest,
                                    size_t length);

/**
 * @brief Computes the BLAKE3 hash in a single operation.
 *
 * This function combines the initialization, update, and finalization
 * steps into a single call. It processes the input data and immediately
 * produces the digest. This is a more convenient alternative when only a
 * single input is available.
 *
 * @param data Pointer to the input data to be hashed.
 * @param length The length of the input data in bytes.
 * @param digest Pointer to a buffer where the resulting digest will be
 * stored.
 * @param digest_length The length of the digest to be produced, in bytes.
 */
HASHA_PUBLIC_FUNC void blake3_oneshot(const uint8_t *data, size_t length,
                                      uint8_t *digest,
                                      size_t digest_length);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_BLAKE3_H_LOADED
