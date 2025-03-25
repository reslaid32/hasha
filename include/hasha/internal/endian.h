/** @file hasha/internal/endian.h */

#ifndef __HASHA_INTERNAL_ENDIAN_H
#define __HASHA_INTERNAL_ENDIAN_H

#if !defined(__BYTE_ORDER__)
#if __has_include(<endian.h>)
/* needs endian.h */
#include <endian.h>
#else
#error "Header <endian.h> is not avaible"
#endif
#endif

/* needs builtin */
#include "./builtin.h"

#if !defined(hi_orders_defined)
#define hi_orders_defined

#if defined(__BYTE_ORDER__)
#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
/* big endian, __leXX is bswapXX */
#define __le16(x) (__builtin_bswap16(x))
#define __le32(x) (__builtin_bswap32(x))
#define __le64(x) (__builtin_bswap64(x))
/* big endian, nothing to do */
#define __be16(x) (x)
#define __be32(x) (x)
#define __be64(x) (x)
#elif (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
/* little endian, nothing to do */
#define __le16(x) (x)
#define __le32(x) (x)
#define __le64(x) (x)
/* little endian, __beXX is bswapXX */
#define __be16(x) (__builtin_bswap16(x))
#define __be32(x) (__builtin_bswap32(x))
#define __be64(x) (__builtin_bswap64(x))
#endif /* __ORDER_..._ENDIAN__ */
#else
#error "Byte order is not defined"
#endif /* __BYTE_ORDER__ */

#endif /* hi_orders_defined */

#endif /* __HASHA_INTERNAL_ENDIAN_H */
