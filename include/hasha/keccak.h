/**
 * @file hasha/keccak.h
 * @brief Header file for Keccak-based hash functions.
 *
 * This header file defines the interface for various Keccak hash
 * functions, including Keccak-224, Keccak-256, Keccak-384, and Keccak-512.
 * It provides macro definitions for the rate and digest sizes of each
 * variant, as well as a common context structure for holding the internal
 * state of the hash computation.
 *
 * The functions declared in this file include those for initializing the
 * context, absorbing input data, finalizing the hash computation, and
 * squeezing out the final digest. Additionally, one-shot operations are
 * provided for convenience.
 *
 * The core transformation is based on the Keccak-f[1600] permutation (see
 * keccak1600.h) and adheres to the specifications set forth in the SHA-3
 * standard.
 *
 * @note The rate and digest sizes are defined in accordance with the SHA-3
 * standard.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf for
 * further details on the SHA-3 standard.
 */

#if !defined(__HASHA_KECCAK_H)
#define __HASHA_KECCAK_H

#include "internal/internal.h"
/* #include "keccak1600.h" */ /* not used in header */

/**
 * @def HA_KECCAK_224_DIGEST_SIZE
 * @brief The digest size for the Keccak-224 hash function.
 *
 * This defines the size of the output hash for Keccak-224, which is 224
 * bits. This value is automatically calculated using the `ha_bB` macro.
 */
#define HA_KECCAK_224_DIGEST_SIZE ha_bB(224)

/**
 * @def HA_KECCAK_256_DIGEST_SIZE
 * @brief The digest size for the Keccak-256 hash function.
 *
 * This defines the size of the output hash for Keccak-256, which is 256
 * bits. This value is automatically calculated using the `ha_bB` macro.
 */
#define HA_KECCAK_256_DIGEST_SIZE ha_bB(256)

/**
 * @def HA_KECCAK_384_DIGEST_SIZE
 * @brief The digest size for the Keccak-384 hash function.
 *
 * This defines the size of the output hash for Keccak-384, which is 384
 * bits. This value is automatically calculated using the `ha_bB` macro.
 */
#define HA_KECCAK_384_DIGEST_SIZE ha_bB(384)

/**
 * @def HA_KECCAK_512_DIGEST_SIZE
 * @brief The digest size for the Keccak-512 hash function.
 *
 * This defines the size of the output hash for Keccak-512, which is 512
 * bits. This value is automatically calculated using the `ha_bB` macro.
 */
#define HA_KECCAK_512_DIGEST_SIZE ha_bB(512)

/** Keccak Padding Byte */
enum ha_pb ha_enum_base(uint8_t)
{
  HA_PB_KECCAK = 0x01,
  HA_PB_SHA3   = 0x06,
};

HA_EXTERN_C_BEG

/**
 * @struct ha_keccak_context
 * @brief Keccak hash state context.
 *
 * This structure holds the internal state of the Keccak hash function. It
 * includes the state array, rate, capacity, and indices for absorbing and
 * squeezing data.
 */
typedef struct ha_keccak_context
{
  /**
   * @brief The Keccak state array.
   *
   * This array holds the internal state of the Keccak hash function (200
   * bytes).
   */
  uint8_t state[200];

  /**
   * @brief The rate (number of bits processed per round).
   *
   * This value indicates the rate of the Keccak hash function for the
   * specific variant (e.g., 136 for Keccak-256).
   */
  size_t  rate;

  /**
   * @brief The capacity (remaining bits).
   *
   * This value holds the capacity of the Keccak function, which defines
   * the number of bits used to absorb the input data.
   */
  size_t  capacity;

  /**
   * @brief The current index for absorbing data.
   *
   * This index keeps track of how much data has been absorbed in the
   * current round.
   */
  size_t  absorb_index;

  /**
   * @brief The current index for squeezing data.
   *
   * This index keeps track of how much data has been squeezed and output
   * in the current round.
   */
  size_t  squeeze_index;
} ha_keccak_context;

/**
 * @brief Initializes the Keccak-Based context.
 *
 * This function initializes the Keccak-Based context to start a new hash
 * computation.
 *
 * @param ctx Pointer to the Keccak-Based context structure to initialize.
 * @param rate The rate of the Keccak-Based algorithm (in bytes)
 */
HA_PUBFUN void ha_keccak_init(ha_keccak_context *ctx, size_t rate);

/**
 * @brief Absorbs data into the Keccak-Based context.
 *
 * This function processes the provided data and updates the Keccak-Based
 * context state.
 *
 * @param ctx Pointer to the Keccak-Based context structure.
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @note The data is absorbed into the context in blocks of size defined by
 *       the rate.
 */
HA_PUBFUN void ha_keccak_update(ha_keccak_context *ctx, ha_inbuf_t buf,
                                size_t len);

/**
 * @brief Finalizes the Keccak-Based computation.
 *
 * This function finals the Keccak-Based hash calculation.
 *
 * @param ctx Pointer to the Keccak-Based context structure.
 * @param digest Pointer to the output buffer where the final hash will be
 * stored.
 * @param digestlen The length of the final hash (in bytes).
 * @note The digest length must match the expected size
 */
HA_PUBFUN void ha_keccak_final(ha_keccak_context *ctx, enum ha_pb padbyte,
                               ha_digest_t digest, size_t digestlen);

/**
 * @brief Computes the Keccak-Based hash in a one-shot operation.
 *
 * This function computes the SHA3 hash of the provided data in a
 * single call. It initializes, absorbs, finals, and squeezes the result
 * internally.
 *
 * @param rate The rate of the Keccak-Based algorithm (in bytes)
 * @param padbyte The padding byte of the Keccak-Based algorithm
 * @param data Pointer to the input data to process.
 * @param length Length of the input data in bytes.
 * @param digest Pointer to the output buffer to store the final
 * Keccak-Based digest.
 */
HA_PUBFUN void ha_keccak_hash(size_t rate, enum ha_pb padbyte,
                              ha_inbuf_t buf, size_t len,
                              ha_digest_t digest, size_t digestlen);

typedef ha_keccak_context ha_keccak_224_context, ha_keccak_256_context,
    ha_keccak_384_context, ha_keccak_512_context;

/**
 * @brief Initializes the Keccak-224 context.
 *
 * This function initializes the context for the Keccak-224 hash function,
 * setting the internal state to the default values.
 *
 * @param ctx Pointer to the Keccak-224 context to be initialized.
 */
HA_PUBFUN void ha_keccak_224_init(ha_keccak_224_context *ctx);

/**
 * @brief Absorbs input data for Keccak-224.
 *
 * This function absorbs the input data into the Keccak-224 context. It
 * processes the input in chunks and updates the internal state.
 *
 * @param ctx Pointer to the Keccak-224 context.
 * @param data Pointer to the input data to be absorbed.
 * @param length The length of the input data in bytes.
 */
HA_PUBFUN void ha_keccak_224_update(ha_keccak_224_context *ctx,
                                    ha_inbuf_t data, size_t length);

/**
 * @brief Finalizes the Keccak-224 context.
 *
 * This function finals the Keccak-224 context after all data has been
 * absorbed, preparing the context for squeezing the hash output.
 *
 * @param ctx Pointer to the Keccak-224 context.
 */
HA_PUBFUN void ha_keccak_224_final(ha_keccak_224_context *ctx,
                                   ha_digest_t            digest);

/**
 * @brief Computes the Keccak-224 hash in a single operation.
 *
 * This function combines the initialization, absorption, finalization, and
 * squeezing steps into a single operation for convenience.
 *
 * @param data Pointer to the input data to be hashed.
 * @param length The length of the input data in bytes.
 * @param digest Pointer to the buffer where the resulting hash will be
 * stored.
 */
HA_PUBFUN void ha_keccak_224_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest);

/**
 * @brief Initializes the Keccak-256 context.
 *
 * This function initializes the context for the Keccak-256 hash function.
 *
 * @param ctx Pointer to the Keccak-256 context to be initialized.
 */
HA_PUBFUN void ha_keccak_256_init(ha_keccak_256_context *ctx);

/**
 * @brief Absorbs input data for Keccak-256.
 *
 * This function absorbs the input data into the Keccak-256 context.
 *
 * @param ctx Pointer to the Keccak-256 context.
 * @param data Pointer to the input data to be absorbed.
 * @param length The length of the input data in bytes.
 */
HA_PUBFUN void ha_keccak_256_update(ha_keccak_256_context *ctx,
                                    ha_inbuf_t data, size_t length);

/**
 * @brief Finalizes the Keccak-256 context.
 *
 * This function finals the Keccak-256 context after all data has been
 * absorbed.
 *
 * @param ctx Pointer to the Keccak-256 context.
 */
HA_PUBFUN void ha_keccak_256_final(ha_keccak_256_context *ctx,
                                   ha_digest_t            digest);

/**
 * @brief Computes the Keccak-256 hash in a single operation.
 *
 * This function combines the initialization, absorption, finalization, and
 * squeezing steps into a single operation for convenience.
 *
 * @param data Pointer to the input data to be hashed.
 * @param length The length of the input data in bytes.
 * @param digest Pointer to the buffer where the resulting hash will be
 * stored.
 */
HA_PUBFUN void ha_keccak_256_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest);

/**
 * @brief Initializes the Keccak-384 context.
 *
 * This function initializes the context for the Keccak-384 hash function.
 */
HA_PUBFUN void ha_keccak_384_init(ha_keccak_384_context *ctx);

/**
 * @brief Absorbs input data for Keccak-384.
 *
 * This function absorbs the input data into the Keccak-384 context.
 */
HA_PUBFUN void ha_keccak_384_update(ha_keccak_384_context *ctx,
                                    ha_inbuf_t data, size_t length);

/**
 * @brief Finalizes the Keccak-384 context.
 *
 * This function finals the Keccak-384 context after all data has been
 * absorbed.
 */
HA_PUBFUN void ha_keccak_384_final(ha_keccak_384_context *ctx,
                                   ha_digest_t            digest);

/**
 * @brief Computes the Keccak-384 hash in a single operation.
 *
 * This function combines the initialization, absorption, finalization, and
 * squeezing steps into a single operation for convenience.
 */
HA_PUBFUN void ha_keccak_384_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest);

/**
 * @brief Initializes the Keccak-512 context.
 *
 * This function initializes the context for the Keccak-512 hash function.
 */
HA_PUBFUN void ha_keccak_512_init(ha_keccak_512_context *ctx);

/**
 * @brief Absorbs input data for Keccak-512.
 *
 * This function absorbs the input data into the Keccak-512 context.
 */
HA_PUBFUN void ha_keccak_512_update(ha_keccak_512_context *ctx,
                                    ha_inbuf_t data, size_t length);

/**
 * @brief Finalizes the Keccak-512 context.
 *
 * This function finals the Keccak-512 context after all data has been
 * absorbed.
 */
HA_PUBFUN void ha_keccak_512_final(ha_keccak_512_context *ctx,
                                   ha_digest_t            digest);

/**
 * @brief Computes the Keccak-512 hash in a single operation.
 *
 * This function combines the initialization, absorption, finalization, and
 * squeezing steps into a single operation for convenience.
 */
HA_PUBFUN void ha_keccak_512_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest);

HA_EXTERN_C_END

#endif  // __HASHA_KECCAK_H
