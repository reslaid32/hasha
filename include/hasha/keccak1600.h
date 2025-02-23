#if !defined(LIBHASHA_KECCAK1600_H_LOADED)
#define LIBHASHA_KECCAK1600_H_LOADED

#include "internal/export.h"
#include "internal/bits.h"
#include "internal/std.h"

#include <stdlib.h>

HASHA_EXTERN_C_BEG

// HASHA_PUBLIC_FUNC void keccakf1600_software(uint64_t *state);

HASHA_PUBLIC_FUNC void keccakf1600(uint64_t *state);

#if defined(__clang__)

  typedef uint64_t _vec200_u64 __attribute__((vector_size(200)));

  HASHA_PUBLIC_FUNC void keccakf1600_clang_vectorized(_vec200_u64 *state);

  HASHA_PUBLIC_HO_FUNC void keccakf1600_clang_vectorized_wrapper(uint64_t *state) {
    __builtin_assume(state != NULL);
    // __builtin_assume_aligned(state, 32);
    keccakf1600_clang_vectorized((_vec200_u64*)state);
  }
#endif

/* gcc */
#if !defined(__clang__) && defined(__GNUC__)
#define __HASHA_NO_VECTORIZE
#endif

#if defined(__clang__) && !defined(__HASHA_NO_VECTORIZE)
#define keccakf1600_do(pstate) keccakf1600_clang_vectorized_wrapper(pstate)
#else
#define keccakf1600_do(pstate) keccakf1600(pstate)
#endif

HASHA_EXTERN_C_END

#endif // LIBHASHA_KECCAK1600_H_LOADED
