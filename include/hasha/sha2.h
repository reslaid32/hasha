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

#if !defined(__HASHA_SHA2_H)
#define __HASHA_SHA2_H

/* dangerous */
#ifdef HA_SHA2_ALIAS_MAP
#define sha224 sha2_256
#define sha256 sha2_256
#define sha384 sha2_384
#define sha512 sha2_512
#endif

#include "internal/internal.h"
/* #include "sha2_k.h" */ /* not used in header */

/**
 * @def HA_SHA2_224_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 224-bit algorithm (64
 * bytes).
 */
#define HA_SHA2_224_BLOCK_SIZE      64

/**
 * @def HA_SHA2_224_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 224-bit algorithm (28
 * bytes).
 */
#define HA_SHA2_224_DIGEST_SIZE     ha_bB(224)

/**
 * @def HA_SHA2_256_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 256-bit algorithm (64
 * bytes).
 */
#define HA_SHA2_256_BLOCK_SIZE      64

/**
 * @def HA_SHA2_256_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 256-bit algorithm (32
 * bytes).
 */
#define HA_SHA2_256_DIGEST_SIZE     ha_bB(256)

/**
 * @def HA_SHA2_384_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 384-bit algorithm (128
 * bytes).
 */
#define HA_SHA2_384_BLOCK_SIZE      128

/**
 * @def HA_SHA2_384_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 384-bit algorithm (48
 * bytes).
 */
#define HA_SHA2_384_DIGEST_SIZE     ha_bB(384)

/**
 * @def HA_SHA2_512_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 512-bit algorithm (128
 * bytes).
 */
#define HA_SHA2_512_BLOCK_SIZE      128

/**
 * @def HA_SHA2_512_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 512-bit algorithm (64
 * bytes).
 */
#define HA_SHA2_512_DIGEST_SIZE     ha_bB(512)

/**
 * @def HA_SHA2_512_224_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 512-224 algorithm (128
 * bytes).
 */
#define HA_SHA2_512_224_BLOCK_SIZE  128

/**
 * @def HA_SHA2_512_224_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 512-224 algorithm (28
 * bytes).
 */
#define HA_SHA2_512_224_DIGEST_SIZE ha_bB(224)

/**
 * @def HA_SHA2_512_256_BLOCK_SIZE
 * @brief The block size in bytes for the SHA-2 512-256 algorithm (128
 * bytes).
 */
#define HA_SHA2_512_256_BLOCK_SIZE  128

/**
 * @def HA_SHA2_512_256_DIGEST_SIZE
 * @brief The digest size in bytes for the SHA-2 512-256 algorithm (32
 * bytes).
 */
#define HA_SHA2_512_256_DIGEST_SIZE ha_bB(256)

HA_EXTERN_C_BEG

/**
 * @struct ha_sha2_224_context
 * @brief Context structure for SHA-2 224-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 224-bit hash computation.
 */
typedef struct ha_sha2_224_context
{
  uint32_t state[8]; /**< Internal state (8 words). */
  uint64_t
          bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[HA_SHA2_224_BLOCK_SIZE]; /**< Buffer used for processing
                                       data in 512-bit blocks. */
} ha_sha2_224_context;

/**
 * @struct ha_sha2_256_context
 * @brief Context structure for SHA-2 256-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 256-bit hash computation.
 */
typedef struct ha_sha2_256_context
{
  uint32_t state[8]; /**< Internal state (8 words). */
  uint64_t
          bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[HA_SHA2_256_BLOCK_SIZE]; /**< Buffer used for processing
                                       data in 512-bit blocks. */
} ha_sha2_256_context;

/**
 * @struct ha_sha2_384_context
 * @brief Context structure for SHA-2 384-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 384-bit hash computation.
 */
typedef struct ha_sha2_384_context
{
  uint64_t state[8];     /**< Internal state (8 words). */
  uint64_t bit_count[2]; /**< Bit count representing the total input
                            length (2 parts). */
  uint8_t  buffer[HA_SHA2_384_BLOCK_SIZE]; /**< Buffer used for processing
                                        data in 512-bit blocks. */
} ha_sha2_384_context;

/**
 * @struct ha_sha2_512_context
 * @brief Context structure for SHA-2 512-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 512-bit hash computation.
 */
typedef struct ha_sha2_512_context
{
  uint64_t state[8]; /**< Internal state (8 words). */
  uint64_t
          bit_count; /**< Bit count representing the total input length. */
  uint8_t buffer[HA_SHA2_512_BLOCK_SIZE]; /**< Buffer used for processing
                                       data in 512-bit blocks. */
} ha_sha2_512_context;

/**
 * @struct ha_sha2_512_224_context
 * @brief Context structure for SHA-2 512-224-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 512-224-bit hash computation.
 */
typedef struct ha_sha2_512_224_context
{
  uint64_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count;     /**< Bit count representing the total input length. */
  uint8_t
      buffer[HA_SHA2_512_224_BLOCK_SIZE]; /**< Buffer used for processing
                                          data in 512-bit blocks. */
} ha_sha2_512_224_context;

/**
 * @struct ha_sha2_512_256_context
 * @brief Context structure for SHA-2 512-256-bit hashing.
 *
 * This structure holds the internal state, bit count, and buffer used
 * during the SHA-2 512-256-bit hash computation.
 */
typedef struct ha_sha2_512_256_context
{
  uint64_t state[8]; /**< Internal state (8 words). */
  uint64_t
      bit_count;     /**< Bit count representing the total input length. */
  uint8_t
      buffer[HA_SHA2_512_256_BLOCK_SIZE]; /**< Buffer used for processing
                                          data in 512-bit blocks. */
} ha_sha2_512_256_context;

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
HA_PUBFUN void ha_sha2_224_transform(ha_sha2_224_context *ctx,
                                     ha_inbuf_t           data);

/**
 * @brief Initializes the SHA-2 224-bit context.
 *
 * This function initializes the SHA-2 224-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 224-bit context structure to initialize.
 */
HA_PUBFUN void ha_sha2_224_init(ha_sha2_224_context *ctx);

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
HA_PUBFUN void ha_sha2_224_update(ha_sha2_224_context *ctx,
                                  ha_inbuf_t data, size_t length);

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
HA_PUBFUN void ha_sha2_224_final(ha_sha2_224_context *ctx,
                                 ha_digest_t          digest);

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
HA_PUBFUN void ha_sha2_224_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest);

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
HA_PUBFUN void ha_sha2_256_transform(ha_sha2_256_context *ctx,
                                     ha_inbuf_t           data);

/**
 * @brief Initializes the SHA-2 256-bit context.
 *
 * This function initializes the SHA-2 256-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 256-bit context structure to initialize.
 */
HA_PUBFUN void ha_sha2_256_init(ha_sha2_256_context *ctx);

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
HA_PUBFUN void ha_sha2_256_update(ha_sha2_256_context *ctx,
                                  ha_inbuf_t data, size_t length);

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
HA_PUBFUN void ha_sha2_256_final(ha_sha2_256_context *ctx,
                                 ha_digest_t          digest);

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
HA_PUBFUN void ha_sha2_256_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest);

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
HA_PUBFUN void ha_sha2_384_transform(ha_sha2_384_context *ctx,
                                     ha_inbuf_t           data);

/**
 * @brief Initializes the SHA-2 384-bit context.
 *
 * This function initializes the SHA-2 384-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 384-bit context structure to initialize.
 */
HA_PUBFUN void ha_sha2_384_init(ha_sha2_384_context *ctx);

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
HA_PUBFUN void ha_sha2_384_update(ha_sha2_384_context *ctx,
                                  ha_inbuf_t data, size_t length);

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
HA_PUBFUN void ha_sha2_384_final(ha_sha2_384_context *ctx,
                                 ha_digest_t          digest);

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
HA_PUBFUN void ha_sha2_384_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest);

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
HA_PUBFUN void ha_sha2_512_transform(ha_sha2_512_context *ctx,
                                     ha_inbuf_t           data);

/**
 * @brief Initializes the SHA-2 512-bit context.
 *
 * This function initializes the SHA-2 512-bit context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA-2 512-bit context structure to initialize.
 */
HA_PUBFUN void ha_sha2_512_init(ha_sha2_512_context *ctx);

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
HA_PUBFUN void ha_sha2_512_update(ha_sha2_512_context *ctx,
                                  ha_inbuf_t data, size_t length);

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
HA_PUBFUN void ha_sha2_512_final(ha_sha2_512_context *ctx,
                                 ha_digest_t          digest);

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
HA_PUBFUN void ha_sha2_512_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest);

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
HA_PUBFUN void ha_sha2_512_224_transform(ha_sha2_512_224_context *ctx,
                                         ha_inbuf_t               data);

/**
 * @brief Initializes the SHA-2 512-224-bit context.
 *
 * This function initializes the SHA-2 512-224-bit context to start a new
 * hash computation.
 *
 * @param ctx Pointer to the SHA-2 512-224-bit context structure to
 * initialize.
 */
HA_PUBFUN void ha_sha2_512_224_init(ha_sha2_512_224_context *ctx);

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
HA_PUBFUN void ha_sha2_512_224_update(ha_sha2_512_224_context *ctx,
                                      ha_inbuf_t data, size_t length);

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
HA_PUBFUN void ha_sha2_512_224_final(ha_sha2_512_224_context *ctx,
                                     ha_digest_t              digest);

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
HA_PUBFUN void ha_sha2_512_224_hash(ha_inbuf_t data, size_t length,
                                    ha_digest_t digest);

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
HA_PUBFUN void ha_sha2_512_256_transform(ha_sha2_512_256_context *ctx,
                                         ha_inbuf_t               data);

/**
 * @brief Initializes the SHA-2 512-256-bit context.
 *
 * This function initializes the SHA-2 512-256-bit context to start a new
 * hash computation.
 *
 * @param ctx Pointer to the SHA-2 512-256-bit context structure to
 * initialize.
 */
HA_PUBFUN void ha_sha2_512_256_init(ha_sha2_512_256_context *ctx);

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
HA_PUBFUN void ha_sha2_512_256_update(ha_sha2_512_256_context *ctx,
                                      ha_inbuf_t data, size_t length);

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
HA_PUBFUN void ha_sha2_512_256_final(ha_sha2_512_256_context *ctx,
                                     ha_digest_t              digest);

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
HA_PUBFUN void ha_sha2_512_256_hash(ha_inbuf_t data, size_t length,
                                    ha_digest_t digest);

HA_EXTERN_C_END

#endif  // __HASHA_SHA2_H
