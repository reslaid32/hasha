#define HA_BUILD

#include "./ver.h"

#include "../include/hasha/internal/ver.h"

#define ha_mkver(ver, maj, min, pat)                                          \
  ver.major = maj;                                                            \
  ver.minor = min;                                                            \
  ver.patch = pat

HA_PUBFUN ha_version_t
ha_version (void)
{
  ha_version_t hashav;
  ha_mkver (hashav, __hasha_maj, __hasha_min, __hasha_pat);
  return hashav;
}
