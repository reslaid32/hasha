#if !defined(LIBHASHA_VER_H_LOADED)
#define LIBHASHA_VER_H_LOADED

#include "export.h"

HASHA_EXTERN_C_BEG

typedef struct HASHA_EXPORT {
    unsigned major, minor, patch;
} hashaver_t;

HASHA_PUBLIC_FUNC hashaver_t hashaver(void);

HASHA_EXTERN_C_END

#endif // LIBHASHA_VER_H_LOADED
