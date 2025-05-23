#define HA_BUILD

#include "../include/hasha/internal/internal.h"

#if ha_has_feature(IO)

#include "../include/hasha/internal/error.h"

#ifndef NOTIME
#include <time.h>
#endif

#include "../include/hasha/internal/opts.h"

HA_PRVFUN
void
ha_basic_throw (FILE *stream, int noabort, int notime, const char *func,
                size_t line, char *level, char *fmt, va_list vargs)
{
#ifndef NOTIME
  time_t rawtime;
  struct tm *timeinfo;
  char timebuf[80];

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  strftime (timebuf, sizeof (timebuf), "%Y-%m-%d %H:%M:%S", timeinfo);
#endif

  fprintf (stream, "%s:%zu: %s: ", func, line, level);
  vfprintf (stream, fmt, vargs);
#ifndef NOTIME
  if (!notime)
    fprintf (stream, "    at %s", timebuf);
#endif
  fprintf (stream, "\n");

  if (noabort)
    return;
  abort ();
}

HA_PUBFUN
void
ha_throw (int noabort, int notime, const char *func, size_t line, char *level,
          char *fmt, ...)
{
  va_list vargs;
  va_start (vargs, fmt);
  ha_basic_throw (stderr, noabort, notime, func, line, level, fmt, vargs);
  va_end (vargs);
}

HA_PUBFUN
void
ha_throwd (int debug, int noabort, int notime, const char *func, size_t line,
           char *level, char *fmt, ...)
{
  if (!debug)
    return;
  va_list vargs;
  va_start (vargs, fmt);
  ha_basic_throw (stderr, noabort, notime, func, line, level, fmt, vargs);
  va_end (vargs);
}

HA_PUBFUN
void
ha_throw_fatal (int notime, const char *func, size_t line, char *fmt, ...)
{
  va_list vargs;
  va_start (vargs, fmt);
  ha_basic_throw (stderr, 0, notime, func, line, "fatal", fmt, vargs);
  va_end (vargs);
}

HA_PUBFUN
void
ha_throw_error (int notime, const char *func, size_t line, char *fmt, ...)
{
  int noabort = 0;
#if 0
  ha_getopt(HA_OPT_NOABORT, &noabort);
#else
  noabort = g_ha_opts.noabort;
#endif

  va_list vargs;
  va_start (vargs, fmt);
  ha_basic_throw (stderr, noabort, notime, func, line, "error", fmt, vargs);
  va_end (vargs);
}

HA_PUBFUN
void
ha_throw_warn (int notime, const char *func, size_t line, char *fmt, ...)
{
  va_list vargs;
  va_start (vargs, fmt);
  ha_basic_throw (stderr, 1, notime, func, line, "warn", fmt, vargs);
  va_end (vargs);
}

HA_PUBFUN
void
ha_throw_debug (int notime, const char *func, size_t line, char *fmt, ...)
{
  int debug = 0;
#if 0
  ha_getopt(HA_OPT_DEBUG, &debug);
#else
  debug = g_ha_opts.debug;
#endif

  if (!debug)
    return;
  va_list vargs;
  va_start (vargs, fmt);
  ha_basic_throw (stderr, 1, notime, func, line, "debug", fmt, vargs);
  va_end (vargs);
}

#endif