
#ifndef __HASHA_INTERNAL_HADEFS_H
#define __HASHA_INTERNAL_HADEFS_H

#ifdef HA_NO_DEPRECATED
#define HA_DEPRECATED(msg)
#endif

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

#if !defined(HA_INL_FUN)
#if defined(_MSC_VER)
#define HA_INL_FUN __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define HA_INL_FUN __inline__ __attribute__((always_inline))
#else
#define HA_INL_FUN inline
#endif
#endif  // HA_INL_FUN

#if !defined(HA_PRVFUN)
#define HA_PRVFUN static HA_INL_FUN
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

#ifndef __ha_alias2
#define __ha_alias2(func) __attribute__((alias(func)))
#endif

#endif