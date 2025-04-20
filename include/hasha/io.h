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

#include "./internal/feature.h"
#include "./internal/hadefs.h"
#include "./internal/internal.h"

HA_EXTERN_C_BEG

#if __HA_FEATURE(IO)

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

#endif /* __HA_FEATURE(IO) */

#define ha_hash2str_bound(len) ((len) * 2)
#define ha_str2hash_bound(len) ((len) / 2)

#define ha_strhash_bound(len)  ha_hash2str_bound(len)

/**
 * @brief Converts a hash digest to a hexadecimal string representation.
 *
 * This function converts the given hash digest (byte array) into a
 * hexadecimal string and stores it in the provided `dst` buffer. Each byte
 * of the digest is converted to a two-character hexadecimal
 * representation.
 *
 * @param dst The destination buffer to store the hexadecimal string.
 * @param src The hash digest (byte array) to convert.
 * @param len The length of the hash digest.
 * @return The number of characters written to `dst`.
 */
HA_PUBFUN
size_t ha_hash2str(char *dst, ha_digest_t src, size_t len);

/**
 * @brief Converts a hexadecimal string representation to a hash digest.
 *
 * This function converts the provided hexadecimal string into its
 * corresponding binary hash digest. Each byte in the resulting digest is
 * represented by two hexadecimal characters in the input string. The
 * conversion stops after processing `len` bytes (i.e. `2 * len` characters
 * from the input string), or earlier if an invalid hexadecimal digit is
 * encountered.
 *
 * @param dst The destination buffer where the binary hash digest will be
 * stored.
 * @param src The source hexadecimal string to be converted. It should
 * contain at least 2 * len valid hexadecimal characters.
 * @param len The expected number of bytes in the binary hash digest.
 * @return The number of bytes successfully converted and written to `dst`.
 */
HA_PUBFUN
size_t ha_str2hash(ha_digest_t dst, const char *src, size_t len);

HA_DEPRECATED("ha_hashstr now deprecated, use ha_hash2str instead")
HA_PUBFUN size_t ha_strhash(char *dst, ha_digest_t src, size_t len);

/**
 * @brief Compares two hash digests byte by byte.
 *
 * This function compares two hash digests (byte arrays) of the same
 * length. It returns `0` if the digests are equal, and a non-zero value if
 * they are different.
 *
 * @param lhs The first hash digest to compare.
 * @param rhs The second hash digest to compare.
 * @param digestlen The length of the hash digests.
 * @return `0` if the digests are equal, or a non-zero value if they are
 * different.
 */
HA_PUBFUN
int ha_cmphash(ha_digest_t lhs, ha_digest_t rhs, size_t digestlen);

/**
 * @brief Compares a hash digest with a hexadecimal string representation.
 *
 * This function compares a hash digest (byte array) with a hexadecimal
 * string. It first converts the hash digest to its string representation
 * and then compares the resulting string with the given hexadecimal
 * string.
 *
 * @param lhs The hash digest to compare.
 * @param rhs The hexadecimal string to compare with.
 * @param digestlen The length of the hash digest.
 * @return `0` if the digest and string are equal, or a non-zero value if
 * they are different.
 */
HA_PUBFUN
int ha_cmphashstr(ha_digest_t lhs, const char *rhs, size_t digestlen);

HA_EXTERN_C_END

#endif
