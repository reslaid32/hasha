
#ifndef __HASHA_INTERNAL_ERROR_H
#define __HASHA_INTERNAL_ERROR_H

#include "./internal.h"

HA_PUBFUN
void ha_throw(int noabort, const char *func, size_t line, char *level,
              char *fmt, ...);

HA_PUBFUN
void ha_throw_fatal(const char *func, size_t line, char *fmt, ...);

HA_PUBFUN
void ha_throw_error(const char *func, size_t line, char *fmt, ...);

HA_PUBFUN
void ha_throw_warn(const char *func, size_t line, char *fmt, ...);

#define ha_curpos __func__, __LINE__
#define ha_assert(cond, message, ...)                                 \
  if (!(cond))                                                        \
  {                                                                   \
    ha_throw_error(ha_curpos, "assertion " #cond " failed: " message, \
                   #__VA_ARGS__);                                     \
  }

#endif