
#ifndef __HASHA_INTERNAL_HADEFS_H
#define __HASHA_INTERNAL_HADEFS_H

#if !defined(HA_DEPRECATED)
#define HA_DEPRECATED(msg) __attribute__((deprecated(msg)))
#endif  // HA_DEPRECATED

#ifdef HA_STATIC
#define HA_EXPORT
#endif

#ifndef HA_EXPORT
#if defined(_WIN32)
#ifdef HA_BUILD
#define HA_EXPORT __declspec(dllexport)
#else
#define HA_EXPORT __declspec(dllimport)
#endif
#else
#ifdef HA_BUILD
#define HA_EXPORT __attribute__((visibility("default")))
#else
#define HA_EXPORT
#endif
#endif
#endif

#if !defined(HA_PUBFUN)
#define HA_PUBFUN HA_EXPORT
#endif  // HA_PUBFUN

#if !defined(HA_PRVFUN)
#if defined(_MSC_VER)
#define HA_PRVFUN static __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define HA_PRVFUN static __inline__ __attribute__((always_inline))
#else
#define HA_PRVFUN static inline
#endif
#endif  // HA_PRVFUN

#if !defined(HA_HDR_PUBFUN)
/* public header only function */
#define HA_HDR_PUBFUN HA_PRVFUN
#endif  // HA_HDR_PUBFUN

#if !defined(HA_EXTERN_C)
#if defined(__cplusplus)
#define HA_EXTERN_C extern "C"
#else
#define HA_EXTERN_C
#endif  // __cplusplus
#endif  // HA_EXTERN_C

#if !defined(HA_EXTERN_C_BEG)
#if defined(__cplusplus)
#define HA_EXTERN_C_BEG                                                   \
  HA_EXTERN_C                                                             \
  {
#else
#define HA_EXTERN_C_BEG
#endif  // __cplusplus
#endif  // HA_EXTERN_C_BEG

#if !defined(HA_EXTERN_C_END)
#if defined(__cplusplus)
#define HA_EXTERN_C_END }
#else
#define HA_EXTERN_C_END
#endif  // __cplusplus
#endif  // HA_EXTERN_C_END

#if !defined(ha_bB)
/* bits to Bytes (bB) */
#define ha_bB(n) n / 8
#endif  // ha_bB

#if !defined(ha_Bb)
/* Bytes to bits (Bb) */
#define ha_Bb(n) n * 8
#endif  // ha_Bb

#ifndef __has_builtin

/* Byte-swap implementations */
#define __builtin_bswap16(x) ((((x) >> 8) & 0xFF) | (((x) & 0xFF) << 8))

#define __builtin_bswap32(x)                                              \
  ((((x) >> 24) & 0xFF) | (((x) >> 8) & 0xFF00) | (((x) & 0xFF00) << 8) | \
   (((x) & 0xFF) << 24))

#define __builtin_bswap64(x)                                              \
  ((((x) >> 56) & 0xFF) | (((x) >> 40) & 0xFF00) |                        \
   (((x) >> 24) & 0xFF0000) | (((x) >> 8) & 0xFF000000) |                 \
   (((x) & 0xFF000000) << 8) | (((x) & 0xFF0000) << 24) |                 \
   (((x) & 0xFF00) << 40) | (((x) & 0xFF) << 56))

/* Expect and assume implementations */
#define __builtin_expect(expr, value)  (expr)
#define __builtin_assume(expr)         ((void)0)
#define __builtin_assume_assigned(var) ((void)(var))

/* Population count */
HA_HDR_PUBFUN int __builtin_popcount(unsigned int x)
{
  int count = 0;
  while (x)
  {
    count  += x & 1;
    x     >>= 1;
  }
  return count;
}

HA_HDR_PUBFUN int __builtin_popcountl(unsigned long x)
{
  return __builtin_popcount((unsigned int)x) +
         __builtin_popcount((unsigned int)(x >> 32));
}

HA_HDR_PUBFUN int __builtin_popcountll(unsigned long long x)
{
  return __builtin_popcountl((unsigned long)x) +
         __builtin_popcountl((unsigned long)(x >> 32));
}

/* Leading and trailing zero count */
HA_HDR_PUBFUN int __builtin_clz(unsigned int x)
{
  int count = 0;
  while (x)
  {
    x >>= 1;
    count++;
  }
  return 32 - count;
}

HA_HDR_PUBFUN int __builtin_clzl(unsigned long x)
{
  return __builtin_clz((unsigned int)x) +
         (sizeof(long) > 4 ? __builtin_clz((unsigned int)(x >> 32)) : 0);
}

HA_HDR_PUBFUN int __builtin_clzll(unsigned long long x)
{
  return __builtin_clzl((unsigned long)x) +
         __builtin_clzl((unsigned long)(x >> 32));
}

#define __builtin_rotateleft32(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))
#define __builtin_rotateright32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define __builtin_rotateleft64(x, n)  (((x) << (n)) | ((x) >> (64 - (n))))
#define __builtin_rotateright64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define __builtin_parity(x)           (__builtin_popcount(x) & 1)

#define __builtin_abs(x)              ((x) < 0 ? -(x) : (x))

#define __builtin_unreachable()

#endif /* !__has_builtin */

#define ha_in_range(x, min, max) ((x) >= (min) && (x) <= (max))

#if defined(__cplusplus)
#define ha_enum_base(T) : T
#else
#define ha_enum_base(T)
#endif

#if !defined(__cplusplus)
#define ha_register register
#else
#define ha_register
#endif

#endif