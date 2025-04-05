#define HA_BUILD

#include "../include/hasha/internal/ver.h"

#define ha_mkver(ver, maj, min, pat) \
  ver.major = maj;                   \
  ver.minor = min;                   \
  ver.patch = pat

HA_PUBFUN ha_version_t ha_version(void)
{
  ha_version_t hashav;
  ha_mkver(hashav, 2, 1, 6);
  return hashav;
}