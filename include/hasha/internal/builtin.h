/** @file hasha/internal/builtin.h */

#ifndef HASHA_INTERNAL_BUILTIN_H
#define HASHA_INTERNAL_BUILTIN_H

/* needs HASHA_PUBLIC_HO_FUNC */
#include "./export.h"

#if defined(__GNUC__) || defined(__clang__)
#if !defined(HIB_AVAILABLE)
#define HIB_AVAILABLE
#endif /* HIB_AVAILABLE */
#endif /* gcc / clang */

#if !defined(HIB_AVAILABLE)

/* Byte-swap implementations */
#define __builtin_bswap16(x) ((((x) >> 8) & 0xFF) | (((x) & 0xFF) << 8))

#define __builtin_bswap32(x)                                              \
  ((((x) >> 24) & 0xFF) | (((x) >> 8) & 0xFF00) | (((x) & 0xFF00) << 8) | \
   (((x) & 0xFF) << 24))

#define __builtin_bswap64(x)                              \
  ((((x) >> 56) & 0xFF) | (((x) >> 40) & 0xFF00) |        \
   (((x) >> 24) & 0xFF0000) | (((x) >> 8) & 0xFF000000) | \
   (((x) & 0xFF000000) << 8) | (((x) & 0xFF0000) << 24) | \
   (((x) & 0xFF00) << 40) | (((x) & 0xFF) << 56))

/* Expect and assume implementations */
#define __builtin_expect(expr, value) (expr)
#define __builtin_assume(expr) ((void)0)
#define __builtin_assume_assigned(var) ((void)(var))

/* Population count */
HASHA_PUBLIC_HO_FUNC int __builtin_popcount(unsigned int x)
{
  int count = 0;
  while (x)
  {
    count += x & 1;
    x >>= 1;
  }
  return count;
}

HASHA_PUBLIC_HO_FUNC int __builtin_popcountl(unsigned long x)
{
  return __builtin_popcount((unsigned int)x) +
         __builtin_popcount((unsigned int)(x >> 32));
}

HASHA_PUBLIC_HO_FUNC int __builtin_popcountll(unsigned long long x)
{
  return __builtin_popcountl((unsigned long)x) +
         __builtin_popcountl((unsigned long)(x >> 32));
}

/* Leading and trailing zero count */
HASHA_PUBLIC_HO_FUNC int __builtin_clz(unsigned int x)
{
  int count = 0;
  while (x)
  {
    x >>= 1;
    count++;
  }
  return 32 - count;
}

HASHA_PUBLIC_HO_FUNC int __builtin_clzl(unsigned long x)
{
  return __builtin_clz((unsigned int)x) +
         (sizeof(long) > 4 ? __builtin_clz((unsigned int)(x >> 32)) : 0);
}

HASHA_PUBLIC_HO_FUNC int __builtin_clzll(unsigned long long x)
{
  return __builtin_clzl((unsigned long)x) +
         __builtin_clzl((unsigned long)(x >> 32));
}

#define __builtin_rotateleft32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define __builtin_rotateright32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define __builtin_rotateleft64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define __builtin_rotateright64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define __builtin_parity(x) (__builtin_popcount(x) & 1)

#define __builtin_abs(x) ((x) < 0 ? -(x) : (x))

#endif /* !HIB_AVAILABLE */

#endif /* HASHA_INTERNAL_BUILTIN_H */
