#ifndef __HASHA_INTERNAL_FEATURE_H
#define __HASHA_INTERNAL_FEATURE_H

#include "config.h"

#define ha_has_feature(Name) __HA_FEATURE(Name)
#define __HA_FEATURE(Name)   __HA_FEATURE__##Name

/* __HA_FEATURE(NEVP) */
#ifndef __HA_FEATURE__NEVP
#define __HA_FEATURE__NEVP 0
#endif /* __HA_FEATURE__NEVP */

/* __HA_FEATURE(EVP) */
#ifndef __HA_FEATURE__EVP
#define __HA_FEATURE__EVP 1
#endif /* __HA_FEATURE__EVP */

/* __HA_FEATURE(IO) */
#ifndef __HA_FEATURE__IO
#define __HA_FEATURE__IO 1
#endif /* __HA_FEATURE__IO */

#endif