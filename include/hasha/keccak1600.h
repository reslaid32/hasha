/**
 * @file hasha/keccak1600.h
 * @brief Keccak-f[1600] permutation implementation for libhasha.
 *
 * This header provides the core Keccak-f[1600] permutation function,
 * which is the fundamental transformation used in Keccak-based hashing
 * algorithms, including SHA-3. The permutation operates on a 1600-bit
 * state and is applied iteratively during the hashing process.
 *
 * @details
 * The Keccak-f[1600] function performs a sequence of nonlinear
 * transformations on a 200-byte state array, following the Keccak
 * permutation rules. This is a key component of Keccak-based cryptographic
 * algorithms. The library provides a generic reference implementation,
 * but optimized implementations may also be available depending on the
 * target architecture.
 *
 * ## Features
 * - Implements the Keccak-f[1600] permutation on a 1600-bit state.
 * - Optimized for performance using platform-specific enhancements where
 * available.
 * - Provides an implementation ID to identify different optimizations.
 *
 * ## References
 * - The Keccak sponge function family: https://keccak.team/
 * - SHA-3 Standard (FIPS 202): https://doi.org/10.6028/NIST.FIPS.202
 *
 * @note This implementation follows the FIPS 202 specification for SHA-3.
 */

#if !defined(LIBHASHA_KECCAK1600_H_LOADED)
#define LIBHASHA_KECCAK1600_H_LOADED

#include <stdlib.h>

#include "internal/internal.h"

HASHA_EXTERN_C_BEG

/**
 * @brief Performs the Keccak-f[1600] permutation on the state.
 *
 * This function applies the Keccak-f[1600] permutation to the 1600-bit
 * state array, which is used as the core transformation for all
 * Keccak-based hashes, including SHA-3. The permutation operates on the
 * internal state of the Keccak algorithm and is typically called during
 * each round of hashing.
 *
 * @param state Pointer to the 1600-bit (200-byte) state array. The state
 * is updated in-place as a result of the permutation.
 */
HASHA_PUBLIC_FUNC void keccakf1600(uint64_t *state);

/**
 * @brief Returns the implementation ID of the Keccak-f[1600] function.
 *
 * This function returns a unique implementation identifier for the
 * Keccakf1600 permutation used in the library. The ID can be used to
 * identify which version or variant of the Keccakf1600 function is being
 * utilized.
 *
 * @return The implementation ID for the Keccakf1600 function.
 *         This ID can be used for debugging, performance tracking, or
 * identifying specific optimizations used in the implementation.
 */
HASHA_PUBLIC_FUNC int hasha_keccakf1600_implid();

HASHA_EXTERN_C_END

#endif  // LIBHASHA_KECCAK1600_H_LOADED
