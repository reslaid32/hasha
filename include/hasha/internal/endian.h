/** @file hasha/internal/builtin.h */

#ifndef HASHA_INTERNAL_ENDIAN_H
#define HASHA_INTERNAL_ENDIAN_H

/* needs builtin */
#include "./builtin.h"

#if !defined(hi_orders_defined)
#define hi_orders_defined

#if defined(__BIG_ENDIAN__) || !defined(__LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
/* big endian, __leXX is bswapXX */
#define __le16(x) (__builtin_bswap16(x))
#define __le32(x) (__builtin_bswap32(x))
#define __le64(x) (__builtin_bswap64(x))
/* big endian, nothing to do */
#define __be16(x) (x)
#define __be32(x) (x)
#define __be64(x) (x)
#elif defined(__LITTLE_ENDIAN__) || !defined(__BIG_ENDIAN__) || \
    (defined(__BYTE_ORDER__) &&                                 \
     __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
/* little endian, nothing to do */
#define __le16(x) (x)
#define __le32(x) (x)
#define __le64(x) (x)
/* little endian, __beXX is bswapXX */
#define __be16(x) (__builtin_bswap16(x))
#define __be32(x) (__builtin_bswap32(x))
#define __be64(x) (__builtin_bswap64(x))
#endif

#endif /* hi_orders_defined */

#endif /* HASHA_INTERNAL_ENDIAN_H */
