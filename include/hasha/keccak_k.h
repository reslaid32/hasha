/**
 * @file hasha/keccak_k.h
 * @brief Keccak Constants for Hash Computation
 */

#if !defined(__HASHA_KECCAK_K_H)
#define __HASHA_KECCAK_K_H

#include "internal/internal.h"

/**
 * @def HA_KECCAK_224_RATE
 * @brief The rate (in bytes) used for the KECCAK/SHA3 224 algorithms.
 */
#define HA_KECCAK_224_RATE 144

/**
 * @def HA_KECCAK_256_RATE
 * @brief The rate (in bytes) used for the KECCAK/SHA3 256 algorithms.
 */
#define HA_KECCAK_256_RATE 136

/**
 * @def HA_KECCAK_384_RATE
 * @brief The rate (in bytes) used for the KECCAK/SHA3 384 algorithms.
 */
#define HA_KECCAK_384_RATE 104

/**
 * @def HA_KECCAK_512_RATE
 * @brief The rate (in bytes) used for the KECCAK/SHA3 512 algorithms.
 */
#define HA_KECCAK_512_RATE 72

#endif  // __HASHA_KECCAK_K_H
