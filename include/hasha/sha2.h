/**
 * @file hasha/sha2.h
 * @brief Header file for SHA-2 cryptographic hash functions.
 *
 * This header file defines the interface for the SHA-2 family of hash
 * algorithms, including SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
 * and SHA-512/256.
 *
 * It provides macro definitions for block and digest sizes, context
 * structures for maintaining the hash state, and declarations for
 * functions that perform the core transformations, initialization,
 * updating, finalization, and one-shot hash computations. The
 * implementation adheres to the standards specified in FIPS 180-4.
 *
 * @note The SHA-2 algorithms defined in this file process data in
 * fixed-size blocks and output a fixed-length digest. They are designed
 * for high performance and security in cryptographic applications.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for
 * further details on SHA-2.
 */

#if !defined(LIBHASHA_SHA2_H_LOADED)
#define LIBHASHA_SHA2_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"
#include "sha2_k.h"

/**
 * @def SHA2_224_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 224-bit algorithm (64
 * bytes).
 */
#define SHA2_224_BLOCK_SIZE 64

/**
 * @def SHA2_224_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 224-bit algorithm (28
 * bytes).
 */
#define SHA2_224_DIGEST_SIZE HASHA_bB(224)

/**
 * @def SHA2_256_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 256-bit algorithm (64
 * bytes).
 */
#define SHA2_256_BLOCK_SIZE 64

/**
 * @def SHA2_256_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 256-bit algorithm (32
 * bytes).
 */
#define SHA2_256_DIGEST_SIZE HASHA_bB(256)

/**
 * @def SHA2_384_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 384-bit algorithm (128
 * bytes).
 */
#define SHA2_384_BLOCK_SIZE 128

/**
 * @def SHA2_384_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 384-bit algorithm (48
 * bytes).
 */
#define SHA2_384_DIGEST_SIZE HASHA_bB(384)

/**
 * @def SHA2_512_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 512-bit algorithm (128
 * bytes).
 */
#define SHA2_512_BLOCK_SIZE 128

/**
 * @def SHA2_512_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 512-bit algorithm (64
 * bytes).
 */
#define SHA2_512_DIGEST_SIZE HASHA_bB(512)

/**
 * @def SHA2_512_224_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 512-224 algorithm (128
 * bytes).
 */
#define SHA2_512_224_BLOCK_SIZE 128

/**
 * @def SHA2_512_224_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 512-224 algorithm (28
 * bytes).
 */
#define SHA2_512_224_DIGEST_SIZE HASHA_bB(224)

/**
 * @def SHA2_512_256_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 512-256 algorithm (128
 * bytes).
 */
#define SHA2_512_256_BLOCK_SIZE 128

/**
 * @def SHA2_512_256_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 512-256 algorithm (32
 * bytes).
 */
#define SHA2_512_256_DIGEST_SIZE HASHA_bB(256)

HASHA_EXTERN_C_BEG

/**
 * @struct sha2_224_context
 * @brief Context structure for SHA-2 224-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 224-bit hash computation.
 */
typedef struct sha2_224_context
{
  uint32_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[SHA2_224_BLOCK_SIZE]; /**< Buffer used for processing data
                                          in 512-bit blocks. */
} sha2_224_context;

/**
 * @struct sha2_256_context
 * @brief Context structure for SHA-2 256-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 256-bit hash computation.
 */
typedef struct sha2_256_context
{
  uint32_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[SHA2_256_BLOCK_SIZE]; /**< Buffer used for processing data
                                          in 512-bit blocks. */
} sha2_256_context;

/**
 * @struct sha2_384_context
 * @brief Context structure for SHA-2 384-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 384-bit hash computation.
 */
typedef struct sha2_384_context
{
  uint64_t state[8];     /**< Internal state (8 words). */
  uint64_t bit_count[2]; /**< Bit count representing the total input length
                            (2 parts). */
  uint8_t buffer[SHA2_384_BLOCK_SIZE]; /**< Buffer used for processing data
                                          in 512-bit blocks. */
} sha2_384_context;

/**
 * @struct sha2_512_context
 * @brief Context structure for SHA-2 512-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 512-bit hash computation.
 */
typedef struct sha2_512_context
{
  uint64_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[SHA2_512_BLOCK_SIZE]; /**< Buffer used for processing data
                                          in 512-bit blocks. */
} sha2_512_context;

/**
 * @struct sha2_512_224_context
 * @brief Context structure for SHA-2 512-224-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 512-224-bit hash computation.
 */
typedef struct sha2_512_224_context
{
  uint64_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[SHA2_512_224_BLOCK_SIZE]; /**< Buffer used for processing
                                              data in 512-bit blocks. */
} sha2_512_224_context;

/**
 * @struct sha2_512_256_context
 * @brief Context structure for SHA-2 512-256-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 512-256-bit hash computation.
 */
typedef struct sha2_512_256_context
{
  uint64_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[SHA2_512_256_BLOCK_SIZE]; /**< Buffer used for processing
                                              data in 512-bit blocks. */
} sha2_512_256_context;

/**
 * @brief Transforms the data in the SHA-2 224-bit context.
 *
 * This function performs the transformation step of the SHA-2 224-bit hash
 * computation. It processes the input data block and updates the internal
 * state of the context.
 *
 * @param ctx Pointer to the SHA-2 224-bit context structure.
 * @param data Pointer to the input data block (64 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_224_transform(sha2_224_context *ctx,
                                          const uint8_t *data);

/**
 * @brief Initializes the SHA-2 224-bit context.
 *
 * This function initializes the SHA-2 224-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 224-bit context structure to initialize.
 */
HASHA_PUBLIC_FUNC void sha2_224_init(sha2_224_context *ctx);

/**
 * @brief Updates the SHA-2 224-bit context with new data.
 *
 * This function processes the provided data and updates the SHA-2 224-bit
 * context state.
 *
 * @param ctx Pointer to the SHA-2 224-bit context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void sha2_224_update(sha2_224_context *ctx,
                                       const uint8_t *data, size_t length);

/**
 * @brief Finalizes the SHA-2 224-bit computation and produces the hash
 * digest.
 *
 * This function finals the SHA-2 224-bit hash calculation and outputs
 * the resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA-2 224-bit context structure.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 224-bit digest (28 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_224_final(sha2_224_context *ctx,
                                      uint8_t *digest);

/**
 * @brief Computes the SHA-2 224-bit hash in a one-shot operation.
 *
 * This function computes the SHA-2 224-bit hash of the provided data in a
 * single call. It initializes, updates, and finals the SHA-2 224-bit
 * computation internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 224-bit digest (28 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_224_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Transforms the data in the SHA-2 256-bit context.
 *
 * This function performs the transformation step of the SHA-2 256-bit hash
 * computation. It processes the input data block and updates the internal
 * state of the context.
 *
 * @param ctx Pointer to the SHA-2 256-bit context structure.
 * @param data Pointer to the input data block (64 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_256_transform(sha2_256_context *ctx,
                                          const uint8_t *data);

/**
 * @brief Initializes the SHA-2 256-bit context.
 *
 * This function initializes the SHA-2 256-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 256-bit context structure to initialize.
 */
HASHA_PUBLIC_FUNC void sha2_256_init(sha2_256_context *ctx);

/**
 * @brief Updates the SHA-2 256-bit context with new data.
 *
 * This function processes the provided data and updates the SHA-2 256-bit
 * context state.
 *
 * @param ctx Pointer to the SHA-2 256-bit context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void sha2_256_update(sha2_256_context *ctx,
                                       const uint8_t *data, size_t length);

/**
 * @brief Finalizes the SHA-2 256-bit computation and produces the hash
 * digest.
 *
 * This function finals the SHA-2 256-bit hash calculation and outputs
 * the resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA-2 256-bit context structure.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 256-bit digest (32 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_256_final(sha2_256_context *ctx,
                                      uint8_t *digest);

/**
 * @brief Computes the SHA-2 256-bit hash in a one-shot operation.
 *
 * This function computes the SHA-2 256-bit hash of the provided data in a
 * single call. It initializes, updates, and finals the SHA-2 256-bit
 * computation internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 256-bit digest (32 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_256_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Transforms the data in the SHA-2 384-bit context.
 *
 * This function performs the transformation step of the SHA-2 384-bit hash
 * computation. It processes the input data block and updates the internal
 * state of the context.
 *
 * @param ctx Pointer to the SHA-2 384-bit context structure.
 * @param data Pointer to the input data block (128 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_384_transform(sha2_384_context *ctx,
                                          const uint8_t *data);

/**
 * @brief Initializes the SHA-2 384-bit context.
 *
 * This function initializes the SHA-2 384-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 384-bit context structure to initialize.
 */
HASHA_PUBLIC_FUNC void sha2_384_init(sha2_384_context *ctx);

/**
 * @brief Updates the SHA-2 384-bit context with new data.
 *
 * This function processes the provided data and updates the SHA-2 384-bit
 * context state.
 *
 * @param ctx Pointer to the SHA-2 384-bit context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void sha2_384_update(sha2_384_context *ctx,
                                       const uint8_t *data, size_t length);

/**
 * @brief Finalizes the SHA-2 384-bit computation and produces the hash
 * digest.
 *
 * This function finals the SHA-2 384-bit hash calculation and outputs
 * the resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA-2 384-bit context structure.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 384-bit digest (48 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_384_final(sha2_384_context *ctx,
                                      uint8_t *digest);

/**
 * @brief Computes the SHA-2 384-bit hash in a one-shot operation.
 *
 * This function computes the SHA-2 384-bit hash of the provided data in a
 * single call. It initializes, updates, and finals the SHA-2 384-bit
 * computation internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 384-bit digest (48 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_384_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Transforms the data in the SHA-2 512-bit context.
 *
 * This function performs the transformation step of the SHA-2 512-bit hash
 * computation. It processes the input data block and updates the internal
 * state of the context.
 *
 * @param ctx Pointer to the SHA-2 512-bit context structure.
 * @param data Pointer to the input data block (128 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_transform(sha2_512_context *ctx,
                                          const uint8_t *data);

/**
 * @brief Initializes the SHA-2 512-bit context.
 *
 * This function initializes the SHA-2 512-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 512-bit context structure to initialize.
 */
HASHA_PUBLIC_FUNC void sha2_512_init(sha2_512_context *ctx);

/**
 * @brief Updates the SHA-2 512-bit context with new data.
 *
 * This function processes the provided data and updates the SHA-2 512-bit
 * context state.
 *
 * @param ctx Pointer to the SHA-2 512-bit context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void sha2_512_update(sha2_512_context *ctx,
                                       const uint8_t *data, size_t length);

/**
 * @brief Finalizes the SHA-2 512-bit computation and produces the hash
 * digest.
 *
 * This function finals the SHA-2 512-bit hash calculation and outputs
 * the resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA-2 512-bit context structure.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 512-bit digest (64 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_final(sha2_512_context *ctx,
                                      uint8_t *digest);

/**
 * @brief Computes the SHA-2 512-bit hash in a one-shot operation.
 *
 * This function computes the SHA-2 512-bit hash of the provided data in a
 * single call. It initializes, updates, and finals the SHA-2 512-bit
 * computation internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 512-bit digest (64 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_oneshot(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Transforms the data in the SHA-2 512-224-bit context.
 *
 * This function performs the transformation step of the SHA-2 512-224-bit
 * hash computation. It processes the input data block and updates the
 * internal state of the context.
 *
 * @param ctx Pointer to the SHA-2 512-224-bit context structure.
 * @param data Pointer to the input data block (128 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_224_transform(sha2_512_224_context *ctx,
                                              const uint8_t *data);

/**
 * @brief Initializes the SHA-2 512-224-bit context.
 *
 * This function initializes the SHA-2 512-224-bit context to start a new
 * hash computation.
 *
 * @param ctx Pointer to the SHA-2 512-224-bit context structure to
 * initialize.
 */
HASHA_PUBLIC_FUNC void sha2_512_224_init(sha2_512_224_context *ctx);

/**
 * @brief Updates the SHA-2 512-224-bit context with new data.
 *
 * This function processes the provided data and updates the SHA-2
 * 512-224-bit context state.
 *
 * @param ctx Pointer to the SHA-2 512-224-bit context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void sha2_512_224_update(sha2_512_224_context *ctx,
                                           const uint8_t *data,
                                           size_t length);

/**
 * @brief Finalizes the SHA-2 512-224-bit computation and produces the hash
 * digest.
 *
 * This function finals the SHA-2 512-224-bit hash calculation and
 * outputs the resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA-2 512-224-bit context structure.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 512-224-bit digest (28 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_224_final(sha2_512_224_context *ctx,
                                          uint8_t *digest);

/**
 * @brief Computes the SHA-2 512-224-bit hash in a one-shot operation.
 *
 * This function computes the SHA-2 512-224-bit hash of the provided data
 * in a single call. It initializes, updates, and finals the SHA-2
 * 512-224-bit computation internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 512-224-bit digest (28 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_224_oneshot(const uint8_t *data,
                                            size_t length,
                                            uint8_t *digest);

/**
 * @brief Transforms the data in the SHA-2 512-256-bit context.
 *
 * This function performs the transformation step of the SHA-2 512-256-bit
 * hash computation. It processes the input data block and updates the
 * internal state of the context.
 *
 * @param ctx Pointer to the SHA-2 512-256-bit context structure.
 * @param data Pointer to the input data block (128 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_256_transform(sha2_512_256_context *ctx,
                                              const uint8_t *data);

/**
 * @brief Initializes the SHA-2 512-256-bit context.
 *
 * This function initializes the SHA-2 512-256-bit context to start a new
 * hash computation.
 *
 * @param ctx Pointer to the SHA-2 512-256-bit context structure to
 * initialize.
 */
HASHA_PUBLIC_FUNC void sha2_512_256_init(sha2_512_256_context *ctx);

/**
 * @brief Updates the SHA-2 512-256-bit context with new data.
 *
 * This function processes the provided data and updates the SHA-2
 * 512-256-bit context state.
 *
 * @param ctx Pointer to the SHA-2 512-256-bit context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void sha2_512_256_update(sha2_512_256_context *ctx,
                                           const uint8_t *data,
                                           size_t length);

/**
 * @brief Finalizes the SHA-2 512-256-bit computation and produces the hash
 * digest.
 *
 * This function finals the SHA-2 512-256-bit hash calculation and
 * outputs the resulting digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA-2 512-256-bit context structure.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 512-256-bit digest (32 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_256_final(sha2_512_256_context *ctx,
                                          uint8_t *digest);

/**
 * @brief Computes the SHA-2 512-256-bit hash in a one-shot operation.
 *
 * This function computes the SHA-2 512-256-bit hash of the provided data
 * in a single call. It initializes, updates, and finals the SHA-2
 * 512-256-bit computation internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA-2
 * 512-256-bit digest (32 bytes).
 */
HASHA_PUBLIC_FUNC void sha2_512_256_oneshot(const uint8_t *data,
                                            size_t length,
                                            uint8_t *digest);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_SHA2_H_LOADED
