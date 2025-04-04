
#ifndef __HASHA_INTERNAL_OPTS_H
#define __HASHA_INTERNAL_OPTS_H

#include "./internal.h"

#define HA_OPT_TYPE_BOOL 0x01000000

#define HA_OPTID_NOABORT 1

#define HA_OPT_NOABORT (HA_OPT_TYPE_BOOL | HA_OPTID_NOABORT)

HA_PUBFUN
int ha_setopt(int opt, ...);

HA_PUBFUN
int ha_getopt(int opt, void *out);

#endif