/**
 * @file hasha/internal/debug.h
 */

#if !defined(HASHA_DEBUG_H_LOADED)
#define HASHA_DEBUG_H_LOADED

#if defined(_HADBG)
#define HASHA_DEBUGGING
#endif

#if defined(HASHA_DEBUGGING)
#include <stdio.h>
#define HASHA_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define HASHA_DEBUG(...)
#endif

#if !defined(ha_dbg)
#define ha_dbg HASHA_DEBUG
#endif

#endif /* HASHA_DEBUG_H_LOADED */