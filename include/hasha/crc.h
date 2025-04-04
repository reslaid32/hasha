/**
 * @file hasha/crc.h
 * @brief Header file for CRC32 checksum calculation.
 *
 * This file provides the definitions and function declaration for
 * computing the CRC32 checksum, a cyclic redundancy check used to detect
 * errors in data. It includes the definition of the CRC32 polynomial and a
 * convenient one-shot function that performs initialization, update, and
 * finalization of the CRC32 calculation in a single call.
 *
 * @note The CRC32 calculation uses the commonly used 32-bit polynomial
 * (0xEDB88320).
 *
 * @see https://en.wikipedia.org/wiki/Cyclic_redundancy_check
 */

#if !defined(__HASHA_CRC_H)
#define __HASHA_CRC_H

#include "internal/internal.h"

/**
 * @def HA_CRC32_POLYNOMIAL
 * @brief The CRC32 polynomial used in the hashing algorithm.
 *
 * This macro defines the polynomial used in the CRC32 calculation. The
 * value corresponds to the commonly used 32-bit CRC polynomial
 * (0xEDB88320).
 */
#define CRC32_POLYNOMIAL 0xEDB88320

HA_EXTERN_C_BEG

/**
 * @brief Computes the CRC32 checksum in a single operation.
 *
 * This function calculates the CRC32 checksum of the given data using the
 * CRC32 algorithm, starting from an initial value of 0xFFFFFFFF and
 * finalizing with a bitwise complement. It is a convenient function that
 * combines the initialization, update, and finalization steps into a
 * single operation.
 *
 * @param data Pointer to the data buffer for which the CRC32 checksum will
 * be computed.
 * @param len The length of the data in bytes.
 *
 * @return The computed CRC32 checksum.
 */
HA_PUBFUN uint32_t ha_crc32_hash(ha_inbuf_t data, size_t len);

HA_EXTERN_C_END

#endif  // __HASHA_CRC_H
