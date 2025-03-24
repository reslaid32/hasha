/** @file hasha/internal/primitive.h */

#ifndef __HASHA_INTERNAL_PRIMITIVE_H
#define __HASHA_INTERNAL_PRIMITIVE_H

#ifndef ha_primitives_defined
#define ha_primitives_defined 1

#define ha_primitive_base_rot(fst, scd, bits, x, n) \
  (((x)fst(n)) | ((x)scd(bits - (n))))
#define ha_primitive_base_rotl(bits, x, n) \
  ha_primitive_base_rot(<<, >>, bits, x, n)
#define ha_primitive_base_rotr(bits, x, n) \
  ha_primitive_base_rot(>>, <<, bits, x, n)

#define ha_primitive_rotl32(x, n) ha_primitive_base_rotl(32, x, n)
#define ha_primitive_rotl64(x, n) ha_primitive_base_rotl(64, x, n)

#define ha_primitive_rotr32(x, n) ha_primitive_base_rotr(32, x, n)
#define ha_primitive_rotr64(x, n) ha_primitive_base_rotr(64, x, n)

#define ha_primitive_shr(x, n) ((x) >> (n))
#define ha_primitive_shl(x, n) ((x) << (n))

#define ha_primitive_ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define ha_primitive_maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* md5 primitives */
#define ha_primitive_md5_f(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define ha_primitive_md5_g(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define ha_primitive_md5_h(x, y, z) ((x) ^ (y) ^ (z))
#define ha_primitive_md5_i(x, y, z) ((y) ^ ((x) | ~(z)))

/* sha2 primitives */
/* Sigma [Σ] */
#define ha_primitive_Sigma0_32(x)                               \
  (ha_primitive_rotr32((x), 2) ^ ha_primitive_rotr32((x), 13) ^ \
   ha_primitive_rotr32((x), 22))
#define ha_primitive_Sigma0_64(x)                            \
  (ha_primitive_rotr64(x, 28) ^ ha_primitive_rotr64(x, 34) ^ \
   ha_primitive_rotr64(x, 39))

#define ha_primitive_Sigma1_32(x)                               \
  (ha_primitive_rotr32((x), 6) ^ ha_primitive_rotr32((x), 11) ^ \
   ha_primitive_rotr32((x), 25))
#define ha_primitive_Sigma1_64(x)                            \
  (ha_primitive_rotr64(x, 14) ^ ha_primitive_rotr64(x, 18) ^ \
   ha_primitive_rotr64(x, 41))

/* sigma [σ] */
#define ha_primitive_sigma0_32(x)                               \
  (ha_primitive_rotr32((x), 7) ^ ha_primitive_rotr32((x), 18) ^ \
   ha_primitive_shr(x, 3))
#define ha_primitive_sigma0_64(x)                          \
  (ha_primitive_rotr64(x, 1) ^ ha_primitive_rotr64(x, 8) ^ \
   ha_primitive_shr(x, 7))

#define ha_primitive_sigma1_32(x)                                \
  (ha_primitive_rotr32((x), 17) ^ ha_primitive_rotr32((x), 19) ^ \
   ((x) >> 10))
#define ha_primitive_sigma1_64(x)                            \
  (ha_primitive_rotr64(x, 19) ^ ha_primitive_rotr64(x, 61) ^ \
   ha_primitive_shr(x, 6))

#endif /* ha_primitives_defined */

#endif /* __HASHA_INTERNAL_PRIMITIVE_H */