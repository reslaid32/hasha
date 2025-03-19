/**
 * @file hasha/internal/ver.h
 */

#if !defined(LIBHASHA_VER_H_LOADED)
#define LIBHASHA_VER_H_LOADED

#include "export.h"

HASHA_EXTERN_C_BEG

typedef struct
{
  unsigned major, minor, patch;
} ha_version_t;

/**
 * @brief Retrieves the version information of the hash library.
 *
 * This function returns the version information for the hash library as a
 * `ha_version_t` structure, which contains the major, minor, and patch
 * version components. This function is typically used to check the library
 * version programmatically.
 *
 * @return A `ha_version_t` structure containing the version:
 *         - `major`: The major version component of the library.
 *         - `minor`: The minor version component of the library.
 *         - `patch`: The patch version component of the library.
 */
HASHA_PUBLIC_FUNC ha_version_t ha_version(void);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_VER_H_LOADED
