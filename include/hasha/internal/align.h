/** @file hasha/internal/align.h */

#ifndef __HASHA_INTERNAL_ALIGN_H
#define __HASHA_INTERNAL_ALIGN_H

#ifndef ha_align_defined
#define ha_align_defined 1

#define ha_alignis(up, n) ((up) & ((n) - 1))
/* yes, up aligned by n bytes */
#define ha_alignis_yes 0

#if defined(__GNUC__) || defined(__clang__) || defined(__TINYC__)
#define ha_aligned(N) __attribute__((aligned(N)))
#endif

#endif /* ha_align_defined */

#endif /* __HASHA_INTERNAL_ALIGN_H */