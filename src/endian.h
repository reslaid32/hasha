#ifndef __hasha_imp_endian_h
#define __hasha_imp_endian_h

#include "../include/hasha/internal/internal.h"

#if defined(__has_include)
#if __has_include(<endian.h>)
#include <endian.h>
#elif __has_include(<sys/endian.h>)
#include <sys/endian.h>
#elif __has_include(<machine/endian.h>)
#include <machine/endian.h>
#endif
#elif defined(__linux__)
#include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#elif defined(__APPLE__)
#include <machine/endian.h>
#elif defined(_WIN32)
#ifndef __ORDER_LITTLE_ENDIAN__
#define __ORDER_LITTLE_ENDIAN__ 1234
#endif
#ifndef __ORDER_BIG_ENDIAN
#define __ORDER_BIG_ENDIAN 4321
#endif
#ifndef __BYTE_ORDER__
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#endif
#else
#error cannot determine endian.h location for this compiler.
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint32_t
le32_to_cpu (uint32_t x)
{
  return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8)
         | ((x & 0xFF000000) >> 24);
}

static inline uint64_t
le64_to_cpu (uint64_t x)
{
  return ((x & 0xFFULL) << 56) | ((x & 0xFF00ULL) << 40)
         | ((x & 0xFF0000ULL) << 24) | ((x & 0xFF000000ULL) << 8)
         | ((x & 0xFF00000000ULL) >> 8) | ((x & 0xFF0000000000ULL) >> 24)
         | ((x & 0xFF000000000000ULL) >> 40)
         | ((x & 0xFF00000000000000ULL) >> 56);
}

static inline uint32_t
load_le32 (const uint8_t *p)
{
  return le32_to_cpu (((uint32_t)p[0]) | ((uint32_t)p[1] << 8)
                      | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static inline uint64_t
load_le64 (const uint8_t *p)
{
  return le64_to_cpu (((uint64_t)p[0]) | ((uint64_t)p[1] << 8)
                      | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
                      | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
                      | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56));
}

static inline void
store_le32 (uint8_t *p, uint32_t x)
{
  p[0] = x & 0xFF;
  p[1] = (x >> 8) & 0xFF;
  p[2] = (x >> 16) & 0xFF;
  p[3] = (x >> 24) & 0xFF;
}

static inline void
store_le64 (uint8_t *p, uint64_t x)
{
  p[0] = x & 0xFF;
  p[1] = (x >> 8) & 0xFF;
  p[2] = (x >> 16) & 0xFF;
  p[3] = (x >> 24) & 0xFF;
  p[4] = (x >> 32) & 0xFF;
  p[5] = (x >> 40) & 0xFF;
  p[6] = (x >> 48) & 0xFF;
  p[7] = (x >> 56) & 0xFF;
}

#define be32_to_cpu(x) (x)
#define be64_to_cpu(x) (x)

static inline uint32_t
load_be32 (const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}

static inline uint64_t
load_be64 (const uint8_t *p)
{
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

static inline void
store_be32 (uint8_t *p, uint32_t x)
{
  memcpy (p, &x, 4);
}

static inline void
store_be64 (uint8_t *p, uint64_t x)
{
  memcpy (p, &x, 8);
}

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)

static inline uint32_t
load_le32 (const uint8_t *p)
{
  uint32_t x;
  memcpy (&x, p, 4);
  return x;
}

static inline uint64_t
load_le64 (const uint8_t *p)
{
  uint64_t x;
  memcpy (&x, p, 8);
  return x;
}

static inline void
store_le32 (uint8_t *p, uint32_t x)
{
  memcpy (p, &x, 4);
}

static inline void
store_le64 (uint8_t *p, uint64_t x)
{
  memcpy (p, &x, 8);
}

static inline uint32_t
be32_to_cpu (uint32_t x)
{
  return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8)
         | ((x & 0xFF000000) >> 24);
}

static inline uint64_t
be64_to_cpu (uint64_t x)
{
  return ((x & 0xFFULL) << 56) | ((x & 0xFF00ULL) << 40)
         | ((x & 0xFF0000ULL) << 24) | ((x & 0xFF000000ULL) << 8)
         | ((x & 0xFF00000000ULL) >> 8) | ((x & 0xFF0000000000ULL) >> 24)
         | ((x & 0xFF000000000000ULL) >> 40)
         | ((x & 0xFF00000000000000ULL) >> 56);
}

static inline uint32_t
load_be32 (const uint8_t *p)
{
  return be32_to_cpu (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                      | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]));
}

static inline uint64_t
load_be64 (const uint8_t *p)
{
  return be64_to_cpu (((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
                      | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
                      | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
                      | ((uint64_t)p[6] << 8) | ((uint64_t)p[7]));
}

static inline void
store_be32 (uint8_t *p, uint32_t x)
{
  p[0] = (x >> 24) & 0xFF;
  p[1] = (x >> 16) & 0xFF;
  p[2] = (x >> 8) & 0xFF;
  p[3] = x & 0xFF;
}

static inline void
store_be64 (uint8_t *p, uint64_t x)
{
  p[0] = (x >> 56) & 0xFF;
  p[1] = (x >> 48) & 0xFF;
  p[2] = (x >> 40) & 0xFF;
  p[3] = (x >> 32) & 0xFF;
  p[4] = (x >> 24) & 0xFF;
  p[5] = (x >> 16) & 0xFF;
  p[6] = (x >> 8) & 0xFF;
  p[7] = x & 0xFF;
}

#else
#error unexpected __BYTE_ORDER__
#endif

#endif