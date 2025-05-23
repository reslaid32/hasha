/** @file hasha/internal/primitive.h */

#ifndef __HASHA_INTERNAL_PRIMITIVE_H
#define __HASHA_INTERNAL_PRIMITIVE_H

#define ha_primitive_base_rot(fst, scd, bits, x, n)                       \
  (((x)fst(n)) | ((x)scd(bits - (n))))
#define ha_primitive_base_rotl(bits, x, n)                                \
  ha_primitive_base_rot(<<, >>, bits, x, n)
#define ha_primitive_base_rotr(bits, x, n)                                \
  ha_primitive_base_rot(>>, <<, bits, x, n)

#define ha_primitive_rotl32(x, n)   ha_primitive_base_rotl(32, x, n)
#define ha_primitive_rotl64(x, n)   ha_primitive_base_rotl(64, x, n)

#define ha_primitive_rotr32(x, n)   ha_primitive_base_rotr(32, x, n)
#define ha_primitive_rotr64(x, n)   ha_primitive_base_rotr(64, x, n)

#define ha_primitive_shr(x, n)      ((x) >> (n))
#define ha_primitive_shl(x, n)      ((x) << (n))

#define ha_primitive_ch(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define ha_primitive_maj(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* md5 primitives */
#define ha_primitive_md5_f(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define ha_primitive_md5_g(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define ha_primitive_md5_h(x, y, z) ((x) ^ (y) ^ (z))
#define ha_primitive_md5_i(x, y, z) ((y) ^ ((x) | ~(z)))

/* sha2 primitives */
/* Sigma [Σ] */
#define ha_primitive_Sigma0_32(x)                                         \
  (ha_primitive_rotr32((x), 2) ^ ha_primitive_rotr32((x), 13) ^           \
   ha_primitive_rotr32((x), 22))
#define ha_primitive_Sigma0_64(x)                                         \
  (ha_primitive_rotr64(x, 28) ^ ha_primitive_rotr64(x, 34) ^              \
   ha_primitive_rotr64(x, 39))

#define ha_primitive_Sigma1_32(x)                                         \
  (ha_primitive_rotr32((x), 6) ^ ha_primitive_rotr32((x), 11) ^           \
   ha_primitive_rotr32((x), 25))
#define ha_primitive_Sigma1_64(x)                                         \
  (ha_primitive_rotr64(x, 14) ^ ha_primitive_rotr64(x, 18) ^              \
   ha_primitive_rotr64(x, 41))

/* sigma [σ] */
#define ha_primitive_sigma0_32(x)                                         \
  (ha_primitive_rotr32((x), 7) ^ ha_primitive_rotr32((x), 18) ^           \
   ha_primitive_shr(x, 3))
#define ha_primitive_sigma0_64(x)                                         \
  (ha_primitive_rotr64(x, 1) ^ ha_primitive_rotr64(x, 8) ^                \
   ha_primitive_shr(x, 7))

#define ha_primitive_sigma1_32(x)                                         \
  (ha_primitive_rotr32((x), 17) ^ ha_primitive_rotr32((x), 19) ^          \
   ((x) >> 10))
#define ha_primitive_sigma1_64(x)                                         \
  (ha_primitive_rotr64(x, 19) ^ ha_primitive_rotr64(x, 61) ^              \
   ha_primitive_shr(x, 6))

#define ha_primitive_blake32_g(sigmatb, r, i, a, b, c, d)                 \
  a += b + m[sigmatb[r][2 * i + 0]];                                      \
  d ^= a;                                                                 \
  d  = (d >> 16) | (d << 16);                                             \
  c += d;                                                                 \
  b ^= c;                                                                 \
  b  = (b >> 12) | (b << 20);                                             \
  a += b + m[sigmatb[r][2 * i + 1]];                                      \
  d ^= a;                                                                 \
  d  = (d >> 8) | (d << 24);                                              \
  c += d;                                                                 \
  b ^= c;                                                                 \
  b  = (b >> 7) | (b << 25);

#define ha_primitive_blake64_g(sigmatb, r, i, a, b, c, d)                 \
  a += b + m[sigmatb[r][2 * i + 0]];                                      \
  d ^= a;                                                                 \
  d  = (d >> 32) | (d << 32);                                             \
  c += d;                                                                 \
  b ^= c;                                                                 \
  b  = (b >> 24) | (b << 40);                                             \
  a += b + m[sigmatb[r][2 * i + 1]];                                      \
  d ^= a;                                                                 \
  d  = (d >> 16) | (d << 48);                                             \
  c += d;                                                                 \
  b ^= c;                                                                 \
  b  = (b >> 63) | (b << 1);

#define ha_primitive_blake_round(sigmatb, g, i)                           \
  g(sigmatb, i, 0, v[0], v[4], v[8], v[12]);                              \
  g(sigmatb, i, 1, v[1], v[5], v[9], v[13]);                              \
  g(sigmatb, i, 2, v[2], v[6], v[10], v[14]);                             \
  g(sigmatb, i, 3, v[3], v[7], v[11], v[15]);                             \
  g(sigmatb, i, 4, v[0], v[5], v[10], v[15]);                             \
  g(sigmatb, i, 5, v[1], v[6], v[11], v[12]);                             \
  g(sigmatb, i, 6, v[2], v[7], v[8], v[13]);                              \
  g(sigmatb, i, 7, v[3], v[4], v[9], v[14]);

#define ha_primitive_blake32_round(sigmatb, i)                            \
  ha_primitive_blake_round(sigmatb, ha_primitive_blake32_g, i)

#define ha_primitive_blake64_round(sigmatb, i)                            \
  ha_primitive_blake_round(sigmatb, ha_primitive_blake64_g, i)

#endif /* __HASHA_INTERNAL_PRIMITIVE_H */