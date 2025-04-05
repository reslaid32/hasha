#define HA_BUILD

#include "../include/hasha/internal/ver.h"

#define mkver(ver, maj, min, pat) \
  ver.major = maj;                \
  ver.minor = min;                \
  ver.patch = pat

HA_PUBFUN ha_version_t ha_version(void)
{
  ha_version_t hashav;
  mkver(hashav, 2, 1, 3);
  return hashav;
}