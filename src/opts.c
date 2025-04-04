#define HA_BUILD

#include "../include/hasha/internal/opts.h"

#include <stdarg.h>

#define HA_OPT_TYPE_MASK 0xFF000000

struct ha_opts
{
  int noabort;
};

struct ha_opts g_ha_opts = {0};

HA_PUBFUN
int ha_setopt(int opt, ...)
{
  va_list args;
  va_start(args, opt);

  int type = opt & HA_OPT_TYPE_MASK;
  int id   = opt & ~HA_OPT_TYPE_MASK;

  switch (type)
  {
    case HA_OPT_TYPE_BOOL:
    {
      long v = va_arg(args, long);
      switch (id)
      {
        case HA_OPTID_NOABORT:
        {
          g_ha_opts.noabort = (v != 0);
          break;
        }
        default:
          return -1;
      }
      break;
    }
    default:
      return -1;
  }
  return 0;
}

HA_PUBFUN
int ha_getopt(int opt, void *out)
{
  int type = opt & HA_OPT_TYPE_MASK;
  int id   = opt & ~HA_OPT_TYPE_MASK;

  switch (type)
  {
    case HA_OPT_TYPE_BOOL:
      switch (id)
      {
        case HA_OPTID_NOABORT:
        {
          *(int *)out = g_ha_opts.noabort;
          break;
        }
      }
  }

  return 0;
}
