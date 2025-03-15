#if !defined(HASHA_DEBUG_H_LOADED)
#define HASHA_DEBUG_H_LOADED

#if defined(HASHA_DEBUGGING)
#include <stdio.h>
#define HASHA_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define HASHA_DEBUG(...)
#endif

#endif /* HASHA_DEBUG_H_LOADED */