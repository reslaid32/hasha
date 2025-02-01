#if !defined(LIBHASHA_KECCAK_PERM_H_LOADED)
#define LIBHASHA_KECCAK_PERM_H_LOADED

#include "export.h"
#include "std.h"

HASHA_EXTERN_C_BEG

HASHA_PUBLIC_FUNC void keccak_permutation_software(uint64_t *state);
HASHA_PUBLIC_FUNC void keccak_permutation(uint64_t *state);

HASHA_EXTERN_C_END

#endif // LIBHASHA_KECCAK_PERM_H_LOADED
