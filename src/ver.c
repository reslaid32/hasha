#define HASHA_LIBRARY_BUILD

#include "../include/hasha/internal/ver.h"

HASHA_PUBLIC_FUNC ha_version_t ha_version(void)
{
  ha_version_t hashav;
  hashav.major = 2;
  hashav.minor = 0;
  hashav.patch = 8;
  return hashav;
}