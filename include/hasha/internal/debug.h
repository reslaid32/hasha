/**
 * @file hasha/internal/debug.h
 */

#if !defined(__HASHA_INTERNAL_DEBUG_H)
#define __HASHA_INTERNAL_DEBUG_H

#if defined(_HADBG)
#define HASHA_DEBUGGING
#endif

#if defined(HASHA_DEBUGGING)
#include "./io.h"
#define HASHA_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define HASHA_DEBUG(...)
#endif

#if !defined(ha_dbg)
#define ha_dbg HASHA_DEBUG
#endif

#endif /* __HASHA_INTERNAL_DEBUG_H */