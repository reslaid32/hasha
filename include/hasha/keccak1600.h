#if !defined(LIBHASHA_KECCAK1600_H_LOADED)
#define LIBHASHA_KECCAK1600_H_LOADED

#include "internal/bits.h"
#include "internal/export.h"
#include "internal/std.h"

#include <stdlib.h>

HASHA_EXTERN_C_BEG

HASHA_PUBLIC_FUNC void keccakf1600(uint64_t *state);

HASHA_EXTERN_C_END

#endif // LIBHASHA_KECCAK1600_H_LOADED
