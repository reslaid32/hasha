#if !defined(LIBHASHA_VER_H_LOADED)
#define LIBHASHA_VER_H_LOADED

#include "export.h"

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT
{
  unsigned major, minor, patch;
} hashaver_t;

/**
 * @brief Retrieves the version information of the hash library.
 *
 * This function returns the version information for the hash library as a
 * `hashaver_t` structure, which contains the major, minor, and patch
 * version components. This function is typically used to check the library
 * version programmatically.
 *
 * @return A `hashaver_t` structure containing the version:
 *         - `major`: The major version component of the library.
 *         - `minor`: The minor version component of the library.
 *         - `patch`: The patch version component of the library.
 */
HASHA_PUBLIC_FUNC hashaver_t hashaver(void);

HASHA_EXTERN_C_END

#endif  // LIBHASHA_VER_H_LOADED
