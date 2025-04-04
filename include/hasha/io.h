/**
 * @file hasha/io.h
 * @brief Header file for I/O operations related to hashing.
 *
 * This file defines the API for handling I/O operations with hash
 * digests, including writing digests to a file stream and outputting
 * digests to the standard output.
 */

#ifndef __HASHA_IO_H
#define __HASHA_IO_H

#include <stdio.h>

#include "./internal/hadefs.h"
#include "./internal/internal.h"

HA_EXTERN_C_BEG

/**
 * @brief Writes the hash digest to the specified file stream.
 *
 * This function writes the given hash digest to the provided file stream.
 * It is useful for storing hash digests in files for later verification or
 * comparison.
 *
 * @param stream The file stream to write the digest to.
 * @param digest The hash digest to write.
 * @param digestlen The length of the hash digest.
 * @return The number of bytes written, or 0 on failure.
 */
HA_PUBFUN
size_t ha_fputhash(FILE *stream, ha_digest_t digest, size_t digestlen);

/**
 * @brief Outputs the hash digest to standard output.
 *
 * This function outputs the given hash digest to the standard output,
 * typically for printing or displaying the result of a hash computation to
 * the user.
 *
 * @param digest The hash digest to output.
 * @param digestlen The length of the hash digest.
 * @return The number of bytes written, or 0 on failure.
 */
HA_PUBFUN
size_t ha_puthash(ha_digest_t digest, size_t digestlen);

HA_EXTERN_C_END

#endif
