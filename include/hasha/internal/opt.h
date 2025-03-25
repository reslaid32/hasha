/** @file hasha/internal/opt.h */

#ifndef __HASHA_INTERNAL_OPT_H
#define __HASHA_INTERNAL_OPT_H

#ifndef ha_opt_helper_defs_defined
#define ha_opt_helper_defs_defined 1
#define ha_str1(S) #S
#define ha_str(S) ha_str1(S)
#define ha_cat(x, y) x##y
#endif

#ifdef _OPENMP
#include <omp.h>
#ifndef HA_OMP
#define HA_OMP(...) _Pragma(ha_str(ha_cat(omp, __VA_ARGS__)))
#endif
#else
#define HA_OMP(...)  // Define empty macro if OpenMP is not available
#endif

#define HA_OMP_PARALLEL_FOR HA_OMP(parallel for)

#endif /* __HASHA_INTERNAL_OPT_H */
