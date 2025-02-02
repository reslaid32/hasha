#if !defined(HASHA_ACEL_H_LOADED)
#define HASHA_ACEL_H_LOADED

#include "export.h"

/* Disable hardware acceleration (legacy code) */
#define HASHA_DISABLE_ACCELERATION

#if !defined(HASHA_ACEL_STATUSES_DEFINED)
#define HASHA_ACEL_STATUSES_DEFINED

#define HASHA_ACCELERATION_DISABLED 0x0
#define HASHA_ACCELERATION_SIMD     0xA
#define HASHA_ACCELERATION_NANO     0xF

#endif // HASHA_ACEL_STATUSES_DEFINED

#if defined(HASHA_DISABLE_ACCELERATION)
  #define HASHA_ACCELERATION HASHA_ACCELERATION_DISABLED
#elif defined(__AVX2__)
  #define HASHA_ACCELERATION HASHA_ACCELERATION_SIMD
#elif defined(__ARM_NEON)
  #define HASHA_ACCELERATION HASHA_ACCELERATION_NANO
#else
  #define HASHA_ACCELERATION HASHA_ACCELERATION_DISABLED
#endif

HASHA_EXTERN_C_BEG

HASHA_DEPRECATED("libhasha hw acceleration deprecated")
HASHA_PUBLIC_FUNC int hashacel(void);

HASHA_EXTERN_C_END

#endif // HASHA_ACEL_H_LOADED
