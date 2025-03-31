/** @file hasha/internal/io.h */

#if !defined(__HASHA_INTERNAL_IO_H)
#define __HASHA_INTERNAL_IO_H

#if !defined(ha_included_stdio)
#define ha_included_stdio 1
#include <stdio.h>
#endif

#include "./opt.h"

#if !defined(ha_hashmacro_defined)
#define ha_hashmacro_defined 1
#define ha_ctx(hash) ha_##hash##_context
#define ha_init(hash, ctx) ha_##hash##_init(ctx)
#define ha_update(hash, ctx, buf, buflen) \
  ha_##hash##_update(ctx, buf, buflen)
#define ha_final(hash, ctx, ...) ha_##hash##_final(ctx, ##__VA_ARGS__)
#define ha_hash(hash, buf, buflen, digest, ...) \
  ha_##hash##_hash(ctx, buf, buflen, digest, ##__VA_ARGS__) l
#endif /* ha_hashmacro_defined */

#if !defined(ha_print_digest)
#define ha_print_digest(stream, digest, digestlen) \
  for (int i = 0; i < digestlen; ++i) fprintf(stream, "%.2x", digest[i])
#endif /* ha_print_digest */

#if !defined(ha_print_newl)
#define ha_print_newl(stream) fprintf(stream, "\n")
#endif /* ha_print_newl */

#if !defined(ha_buffer_digest)
#define ha_buffer_digest(hash, buf, len, digest, ...) \
  do {                                                \
    ha_ctx(hash) ctx;                                 \
    ha_init(hash, &ctx);                              \
    ha_update(hash, &ctx, buf, len);                  \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__);      \
  } while (0)
#endif /* ha_buffer_digest */

#if !defined(ha_stream_digest)
#define ha_stream_digest(hash, stream, size, chunksize, buffer, digest,  \
                         ...)                                            \
  do {                                                                   \
    ha_ctx(hash) ctx;                                                    \
    ha_init(hash, &ctx);                                                 \
    size_t bytes;                                                        \
    while ((bytes = fread((buffer), (size), (chunksize), (stream))) > 0) \
    {                                                                    \
      ha_update(hash, &ctx, buffer, bytes);                              \
    }                                                                    \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__);                         \
  } while (0)
#endif /* ha_stream_digest */

#endif /* __HASHA_INTERNAL_IO_H */