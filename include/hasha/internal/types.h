/** @file hasha/internal/types.h */

#ifndef __HASHA_INTERNAL_TYPES_H
#define __HASHA_INTERNAL_TYPES_H

#include "./std.h"
#define __ha_byte uint8_t
#define __ha_buf __ha_byte*
#define __ha_in_buf_type const __ha_buf
#define __ha_out_buf_type __ha_buf

typedef __ha_in_buf_type ha_inbuf_t;
typedef __ha_out_buf_type ha_outbuf_t;

typedef ha_outbuf_t ha_digest_t;

#endif /* __HASHA_INTERNAL_TYPES_H */
