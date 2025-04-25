
#ifndef __HASHA_INTERNAL_ERROR_H
#define __HASHA_INTERNAL_ERROR_H

#include "./internal.h"

#if ha_has_feature(IO)

HA_PUBFUN
void ha_throw(int noabort, int notime, const char *func, size_t line,
              char *level, char *fmt, ...);
HA_PUBFUN
void ha_throwd(int debug, int noabort, int notime, const char *func,
               size_t line, char *level, char *fmt, ...);

HA_PUBFUN
void ha_throw_fatal(int notime, const char *func, size_t line, char *fmt,
                    ...);

HA_PUBFUN
void ha_throw_error(int notime, const char *func, size_t line, char *fmt,
                    ...);

HA_PUBFUN
void ha_throw_warn(int notime, const char *func, size_t line, char *fmt,
                   ...);

#if defined(NDEBUG)
#define ha_throw_debug(...)
#else
HA_PUBFUN
void ha_throw_debug(int notime, const char *func, size_t line, char *fmt,
                    ...);
#endif

#define ha_curpos __func__, __LINE__
#define ha_assert(cond, message, ...)                                     \
  if (!(cond))                                                            \
  {                                                                       \
    ha_throw_error(0, ha_curpos, "assertion " #cond " failed: " message,  \
                   #__VA_ARGS__);                                         \
  }

#else

#define ha_throw(...)
#define ha_throwd(...)
#define ha_throw_fatal(...)
#define ha_throw_error(func, line, fmt, ...)
#define ha_throw_warn(...)
#define ha_throw_debug(...)
#define ha_curpos

/* bug fix */
#define ha_assert(cond, message, ...) (void)cond

#endif

#endif