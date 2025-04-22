#ifndef __HASHA_INTERNAL_FEATURE_H
#define __HASHA_INTERNAL_FEATURE_H

#define ha_has_feature(Name) __HA_FEATURE(Name)
#define __HA_FEATURE(Name)   __HA_FEATURE__##Name

/* __HA_FEATURE(EVP) */
#ifndef __HA_FEATURE__EVP
#define __HA_FEATURE__EVP 1
#endif /* __HA_FEATURE__EVP */

/* __HA_FEATURE(IO) */
#ifndef __HA_FEATURE__IO
#define __HA_FEATURE__IO 1
#endif /* __HA_FEATURE__IO */

#endif