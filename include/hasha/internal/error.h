
#ifndef __HASHA_INTERNAL_ERROR_H
#define __HASHA_INTERNAL_ERROR_H

#include "./internal.h"

#if ha_has_feature(IO)

HA_PUBFUN
void ha_throw(int noabort, const char *func, size_t line, char *level,
              char *fmt, ...);

HA_PUBFUN
void ha_throwd(int debug, int noabort, const char *func, size_t line,
               char *level, char *fmt, ...);

HA_PUBFUN
void ha_throw_fatal(const char *func, size_t line, char *fmt, ...);

HA_PUBFUN
void ha_throw_error(const char *func, size_t line, char *fmt, ...);

HA_PUBFUN
void ha_throw_warn(const char *func, size_t line, char *fmt, ...);

#if defined(NDEBUG)
#define ha_throw_debug(...)
#else
HA_PUBFUN
void ha_throw_debug(const char *func, size_t line, char *fmt, ...);
#endif

#define ha_curpos __func__, __LINE__
#define ha_assert(cond, message, ...)                                     \
  if (!(cond))                                                            \
  {                                                                       \
    ha_throw_error(ha_curpos, "assertion " #cond " failed: " message,     \
                   #__VA_ARGS__);                                         \
  }

#else

#define ha_throw(...)
#define ha_throwd(...)
#define ha_throw_fatal(...)
#define ha_throw_error(...)
#define ha_throw_error(...)
#define ha_throw_warn(...)
#define ha_throw_debug(...)
#define ha_curpos
#define ha_assert(...)

#endif

#endif