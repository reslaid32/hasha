/**
 * @file hasha/sha1_k.h
 * @brief SHA-1 Constants for Hash Computation
 */

#if !defined(__HASHA_SHA1_K_H)
#define __HASHA_SHA1_K_H

#include "internal/internal.h"

/**
 * @brief SHA-1 constant K values used in the transformation function.
 */
static const uint32_t HA_SHA1_K[4]  = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
                                       0xCA62C1D6};

/**
 * @brief SHA-1 initial hash values.
 */
static const uint32_t HA_SHA1_H0[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                       0x10325476, 0xC3D2E1F0};

#endif  // __HASHA_SHA1_K_H
