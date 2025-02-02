#if !defined(LIBHASHA_KECCAK1600_H_LOADED)
#define LIBHASHA_KECCAK1600_H_LOADED

#include "export.h"
#include "std.h"

HASHA_EXTERN_C_BEG

// HASHA_PUBLIC_FUNC void keccakf1600_software(uint64_t *state);
HASHA_PUBLIC_FUNC void keccakf1600(uint64_t *state);

HASHA_EXTERN_C_END

#endif // LIBHASHA_KECCAK1600_H_LOADED
