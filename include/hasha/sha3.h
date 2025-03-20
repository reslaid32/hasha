/**
 * @file hasha/sha3.h
 * @brief Header file for SHA3 cryptographic hash functions.
 *
 * This header file defines the interface for the SHA3 family of hash
 * functions, including SHA3-224, SHA3-256, SHA3-384, and SHA3-512. It
 * provides macro definitions for the rate and digest sizes of each
 * variant, a common context structure for holding the internal state
 * during the hashing process, and function declarations for initializing,
 * absorbing data, finalizing, squeezing the digest, and performing
 * one-shot hash computations.
 *
 * The SHA3 functions utilize the Keccak-f[1600] permutation (see
 * keccak1600.h) as the core transformation. The library processes input
 * data in chunks and generates a hash digest according to the variant's
 * specification.
 *
 * @note The rate and digest sizes are defined in accordance with the SHA3
 * standard.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf for
 * further details on the SHA3 standard.
 */

#if !defined(LIBHASHA_SHA3_H_LOADED)
#define LIBHASHA_SHA3_H_LOADED

#include "internal/internal.h"
/* #include "keccak1600.h" */ /* not used in header */

#define KECCAK_ROUNDS 24

/**
 * @def SHA3_224_RATE
 * @brief The rate (in bytes) used for the SHA3-224 algorithm.
 */
#define SHA3_224_RATE 144

/**
 * @def SHA3_224_DIGEST_SIZE
 * @brief The digest size (in bytes) for the SHA3-224 algorithm (224 bits).
 */
#define SHA3_224_DIGEST_SIZE HASHA_bB(224)

/**
 * @def SHA3_256_RATE
 * @brief The rate (in bytes) used for the SHA3-256 algorithm.
 */
#define SHA3_256_RATE 136

/**
 * @def SHA3_256_DIGEST_SIZE
 * @brief The digest size (in bytes) for the SHA3-256 algorithm (256 bits).
 */
#define SHA3_256_DIGEST_SIZE HASHA_bB(256)

/**
 * @def SHA3_384_RATE
 * @brief The rate (in bytes) used for the SHA3-384 algorithm.
 */
#define SHA3_384_RATE 104

/**
 * @def SHA3_384_DIGEST_SIZE
 * @brief The digest size (in bytes) for the SHA3-384 algorithm (384 bits).
 */
#define SHA3_384_DIGEST_SIZE HASHA_bB(384)

/**
 * @def SHA3_512_RATE
 * @brief The rate (in bytes) used for the SHA3-512 algorithm.
 */
#define SHA3_512_RATE 72

/**
 * @def SHA3_512_DIGEST_SIZE
 * @brief The digest size (in bytes) for the SHA3-512 algorithm (512 bits).
 */
#define SHA3_512_DIGEST_SIZE HASHA_bB(512)

HASHA_EXTERN_C_BEG

/**
 * @struct ha_sha3_context
 * @brief The context structure used by all SHA3 variants.
 *
 * This structure holds the internal state, rate, capacity, and indexes
 * used during the SHA3 hashing process.
 */
typedef struct ha_sha3_context
{
  uint8_t state[200]; /**< State array used during the SHA3 computation. */
  size_t rate;        /**< Rate of the SHA3 algorithm. */
  size_t capacity;    /**< Capacity of the SHA3 algorithm. */
  size_t absorb_index;  /**< Index for the absorb phase. */
  size_t squeeze_index; /**< Index for the squeeze phase. */
} ha_sha3_context;

typedef ha_sha3_context ha_sha3_224_context, ha_sha3_256_context,
    ha_sha3_384_context, ha_sha3_512_context;

/**
 * @brief Initializes the SHA3-224 context.
 *
 * This function initializes the SHA3-224 context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA3-224 context structure to initialize.
 */
HASHA_PUBLIC_FUNC void ha_sha3_224_init(ha_sha3_224_context *ctx);

/**
 * @brief Absorbs data into the SHA3-224 context.
 *
 * This function processes the provided data and updates the SHA3-224
 * context state.
 *
 * @param ctx Pointer to the SHA3-224 context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void ha_sha3_224_absorb(ha_sha3_224_context *ctx,
                                          const uint8_t *data,
                                          size_t length);

/**
 * @brief Finalizes the SHA3-224 computation.
 *
 * This function finals the SHA3-224 hash calculation.
 *
 * @param ctx Pointer to the SHA3-224 context structure.
 */
HASHA_PUBLIC_FUNC void ha_sha3_224_final(ha_sha3_224_context *ctx);

/**
 * @brief Produces the final SHA3-224 hash digest.
 *
 * This function squeezes the resulting hash and stores the final SHA3-224
 * digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA3-224 context structure.
 * @param digest Pointer to the output buffer to store the final hash
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_224_squeeze(ha_sha3_224_context *ctx,
                                           uint8_t *digest);

/**
 * @brief Computes the SHA3-224 hash in a one-shot operation.
 *
 * This function computes the SHA3-224 hash of the provided data in a
 * single call. It initializes, absorbs, finals, and squeezes the result
 * internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA3-224
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_224_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Initializes the SHA3-256 context.
 *
 * This function initializes the SHA3-256 context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA3-256 context structure to initialize.
 */
HASHA_PUBLIC_FUNC void ha_sha3_256_init(ha_sha3_256_context *ctx);

/**
 * @brief Absorbs data into the SHA3-256 context.
 *
 * This function processes the provided data and updates the SHA3-256
 * context state.
 *
 * @param ctx Pointer to the SHA3-256 context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void ha_sha3_256_absorb(ha_sha3_256_context *ctx,
                                          const uint8_t *data,
                                          size_t length);

/**
 * @brief Finalizes the SHA3-256 computation.
 *
 * This function finals the SHA3-256 hash calculation.
 *
 * @param ctx Pointer to the SHA3-256 context structure.
 */
HASHA_PUBLIC_FUNC void ha_sha3_256_final(ha_sha3_256_context *ctx);

/**
 * @brief Produces the final SHA3-256 hash digest.
 *
 * This function squeezes the resulting hash and stores the final SHA3-256
 * digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA3-256 context structure.
 * @param digest Pointer to the output buffer to store the final hash
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_256_squeeze(ha_sha3_256_context *ctx,
                                           uint8_t *digest);

/**
 * @brief Computes the SHA3-256 hash in a one-shot operation.
 *
 * This function computes the SHA3-256 hash of the provided data in a
 * single call. It initializes, absorbs, finals, and squeezes the result
 * internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA3-256
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_256_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Initializes the SHA3-384 context.
 *
 * This function initializes the SHA3-384 context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA3-384 context structure to initialize.
 */
HASHA_PUBLIC_FUNC void ha_sha3_384_init(ha_sha3_384_context *ctx);

/**
 * @brief Absorbs data into the SHA3-384 context.
 *
 * This function processes the provided data and updates the SHA3-384
 * context state.
 *
 * @param ctx Pointer to the SHA3-384 context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void ha_sha3_384_absorb(ha_sha3_384_context *ctx,
                                          const uint8_t *data,
                                          size_t length);

/**
 * @brief Finalizes the SHA3-384 computation.
 *
 * This function finals the SHA3-384 hash calculation.
 *
 * @param ctx Pointer to the SHA3-384 context structure.
 */
HASHA_PUBLIC_FUNC void ha_sha3_384_final(ha_sha3_384_context *ctx);

/**
 * @brief Produces the final SHA3-384 hash digest.
 *
 * This function squeezes the resulting hash and stores the final SHA3-384
 * digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA3-384 context structure.
 * @param digest Pointer to the output buffer to store the final hash
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_384_squeeze(ha_sha3_384_context *ctx,
                                           uint8_t *digest);

/**
 * @brief Computes the SHA3-384 hash in a one-shot operation.
 *
 * This function computes the SHA3-384 hash of the provided data in a
 * single call. It initializes, absorbs, finals, and squeezes the result
 * internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA3-384
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_384_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest);

/**
 * @brief Initializes the SHA3-512 context.
 *
 * This function initializes the SHA3-512 context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the SHA3-512 context structure to initialize.
 */
HASHA_PUBLIC_FUNC void ha_sha3_512_init(ha_sha3_512_context *ctx);

/**
 * @brief Absorbs data into the SHA3-512 context.
 *
 * This function processes the provided data and updates the SHA3-512
 * context state.
 *
 * @param ctx Pointer to the SHA3-512 context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 */
HASHA_PUBLIC_FUNC void ha_sha3_512_absorb(ha_sha3_512_context *ctx,
                                          const uint8_t *data,
                                          size_t length);

/**
 * @brief Finalizes the SHA3-512 computation.
 *
 * This function finals the SHA3-512 hash calculation.
 *
 * @param ctx Pointer to the SHA3-512 context structure.
 */
HASHA_PUBLIC_FUNC void ha_sha3_512_final(ha_sha3_512_context *ctx);

/**
 * @brief Produces the final SHA3-512 hash digest.
 *
 * This function squeezes the resulting hash and stores the final SHA3-512
 * digest into the provided buffer.
 *
 * @param ctx Pointer to the SHA3-512 context structure.
 * @param digest Pointer to the output buffer to store the final hash
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_512_squeeze(ha_sha3_512_context *ctx,
                                           uint8_t *digest);

/**
 * @brief Computes the SHA3-512 hash in a one-shot operation.
 *
 * This function computes the SHA3-512 hash of the provided data in a
 * single call. It initializes, absorbs, finals, and squeezes the result
 * internally.
 *
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final SHA3-512
 * digest.
 */
HASHA_PUBLIC_FUNC void ha_sha3_512_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_SHA3_H_LOADED
