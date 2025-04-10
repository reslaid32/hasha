
#ifndef __HASHA_INTERNAL_OPTS_H
#define __HASHA_INTERNAL_OPTS_H

#include "./internal.h"

#define HA_OPT_TYPE_BOOL 0x01000000

#define HA_OPTID_NOABORT 1
#define HA_OPTID_DEBUG   2
#define HA_OPTID_FASTCMP 3

#define HA_OPT_NOABORT   (HA_OPT_TYPE_BOOL | HA_OPTID_NOABORT)
#define HA_OPT_DEBUG     (HA_OPT_TYPE_BOOL | HA_OPTID_DEBUG)

struct ha_opts
{
  int noabort, debug;
};

extern struct ha_opts g_ha_opts;

HA_DEPRECATED("use g_ha_opts instead")
HA_PUBFUN
int ha_setopt(int opt, ...);

HA_DEPRECATED("use g_ha_opts instead")
HA_PUBFUN
int ha_getopt(int opt, void *out);

#endif