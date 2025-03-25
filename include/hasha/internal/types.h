/** @file hasha/internal/types.h */

#ifndef __HASHA_INTERNAL_TYPES_H
#define __HASHA_INTERNAL_TYPES_H

#ifndef ha_types_defined
#include "./std.h"
#define __ha_byte uint8_t
#define __ha_buf __ha_byte*
#define __ha_in_buf_type const __ha_buf
#define __ha_out_buf_type __ha_buf
typedef __ha_buf ha_buf_t;
typedef __ha_in_buf_type ha_inbuf_t;
typedef __ha_out_buf_type ha_outbuf_t;
typedef ha_outbuf_t ha_digest_t;
#define ha_types_defined
#endif /* ha_types_defined */

#if !defined(ha_hashmacro_defined)
#define ha_hashmacro_defined 1
#define ha_ctx(hash) ha_##hash##_context
#define ha_init(hash, ctx) ha_##hash##_init(ctx)
#define ha_update(hash, ctx, buf, buflen) \
  ha_##hash##_update(ctx, buf, buflen)
#define ha_absorb(hash, ctx, buf, buflen) \
  ha_##hash##_absorb(ctx, buf, buflen)
#define ha_final(hash, ctx, ...) ha_##hash##_final(ctx, ##__VA_ARGS__)
#define ha_squeeze(hash, ctx, digest, ...) \
  ha_##hash##_squeeze(ctx, digest, ##__VA_ARGS__)
#define ha_hash(hash, buf, buflen, digest, ...) \
  ha_##hash##_hash(ctx, buf, buflen, digest, ##__VA_ARGS__) l
#endif /* ha_hashmacro_defined */

#endif /* __HASHA_INTERNAL_TYPES_H */
