#define HASHA_LIBRARY_BUILD

#include "../include/hasha/internal/ver.h"

HASHA_PUBLIC_FUNC hashaver_t hashaver(void) {
    hashaver_t hashav;
    hashav.major = 1;
    hashav.minor = 0;
    hashav.patch = 8;
    return hashav;
}