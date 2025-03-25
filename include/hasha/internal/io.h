/** @file hasha/internal/io.h */

#if !defined(__HASHA_INTERNAL_IO_H)
#define __HASHA_INTERNAL_IO_H

#if !defined(ha_included_stdio)
#define ha_included_stdio 1
#include <stdio.h>
#endif

#include "./opt.h"
#include "./types.h" /* need ha hasher construction */

typedef FILE *ha_stream_t;

#if !defined(ha_print_digest)
#define ha_print_digest(stream, digest, digestlen) \
  for (int i = 0; i < digestlen; ++i) fprintf(stream, "%.2x", digest[i])
#endif /* ha_print_digest */

#if !defined(ha_buffer_digest)
#define ha_buffer_digest(hash, buf, len, digest, ...) \
  do {                                                \
    ha_ctx(hash) ctx;                                 \
    ha_init(hash, ctx);                               \
    ha_update(hash, ctx, buf, len);                   \
    ha_final(hash, ctx, digest, ##__VA_ARGS__);       \
  } while (0)
#endif /* ha_buffer_digest */

#if !defined(ha_stream_digest)
#define ha_stream_digest(hash, stream, size, chunksize, buffer, digest,  \
                         ...)                                            \
  do {                                                                   \
    ha_ctx(hash) ctx;                                                    \
    ha_init(hash, &ctx);                                                 \
    size_t bytes;                                                        \
    HA_OMP(parallel)                                                     \
    while ((bytes = fread((buffer), (size), (chunksize), (stream))) > 0) \
    {                                                                    \
      HA_OMP(task) ha_update(hash, &ctx, buffer, bytes);                 \
    }                                                                    \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__);                         \
  } while (0)
#endif /* ha_stream_digest */

#if !defined(ha_stream_digest_sha3)
#define ha_stream_digest_sha3(hash, stream, size, chunksize, buffer,     \
                              digest, ...)                               \
  do {                                                                   \
    ha_ctx(hash) ctx;                                                    \
    ha_init(hash, &ctx);                                                 \
    size_t bytes;                                                        \
    while ((bytes = fread((buffer), (size), (chunksize), (stream))) > 0) \
    {                                                                    \
      ha_absorb(hash, &ctx, buffer, bytes);                              \
    }                                                                    \
    ha_final(hash, &ctx);                                                \
    ha_squeeze(hash, &ctx, digest, ##__VA_ARGS__);                       \
  } while (0)
#endif /* ha_stream_digest_sha3 */

#endif /* __HASHA_INTERNAL_IO_H */