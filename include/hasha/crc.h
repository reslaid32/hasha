#if !defined(LIBHASHA_CRC_H_LOADED)
#define LIBHASHA_CRC_H_LOADED

#include "export.h"

#include <stdint.h>
#include <stddef.h>

#define CRC32_POLYNOMIAL 0xEDB88320

HASHA_EXTERN_C_BEG

HASHA_EXPORT HASHA_INLINE void      crc32_init_table(uint32_t *crc_table);
HASHA_EXPORT HASHA_INLINE uint32_t  crc32(const uint8_t *data, size_t len);

HASHA_EXTERN_C_END

#endif // LIBHASHA_CRC_H_LOADED
