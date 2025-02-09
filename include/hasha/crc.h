#if !defined(LIBHASHA_CRC_H_LOADED)
#define LIBHASHA_CRC_H_LOADED

#include "internal/export.h"
#include "internal/bits.h"
#include "internal/std.h"

#define CRC32_POLYNOMIAL 0xEDB88320

HASHA_EXTERN_C_BEG

HASHA_PUBLIC_FUNC uint32_t crc32(const uint8_t *data, size_t len);

HASHA_EXTERN_C_END

#endif // LIBHASHA_CRC_H_LOADED
