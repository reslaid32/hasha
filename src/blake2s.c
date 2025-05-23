#define HA_BUILD

#include "../include/hasha/blake2s.h"
#include "../include/hasha/blake2s_k.h"

#include "./endian.h"

HA_PRVFUN void
ha_blake2s_compress (ha_blake2s_context *ctx, const uint8_t block[64])
{
  uint32_t v[16], m[16];
  int i;

  for (i = 0; i < 8; i++)
    {
      v[i] = ctx->h[i];
      v[i + 8] = HA_BLAKE2S_H0[i];
    }

  v[12] ^= ctx->t[0];
  v[13] ^= ctx->t[1];
  v[14] ^= ctx->f[0];
  v[15] ^= ctx->f[1];

#ifdef HA_ONLY_LE
  for (i = 0; i < 16; i++)
    m[i] = ((uint32_t *)block)[i];
#else
  for (i = 0; i < 16; i++)
    {
      uint32_t word;
      memcpy (&word, block + i * 4, 4);
      m[i] = le32_to_cpu (word);
    }
#endif

  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 0);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 1);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 2);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 3);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 4);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 5);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 6);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 7);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 8);
  ha_primitive_blake32_round (HA_BLAKE2S_SIGMA, 9);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

HA_PUBFUN void
ha_blake2s_init (ha_blake2s_context *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  memcpy (ctx->h, HA_BLAKE2S_H0, sizeof (ctx->h));
}

HA_PUBFUN void
ha_blake2s_update (ha_blake2s_context *ctx, ha_inbuf_t data, size_t len)
{
  while (len > 0)
    {
      size_t fill = 64 - ctx->buflen;
      size_t to_copy = len < fill ? len : fill;
      memcpy (ctx->buf + ctx->buflen, data, to_copy);
      ctx->buflen += to_copy;
      data += to_copy;
      len -= to_copy;

      if (ctx->buflen == 64)
        {
          ctx->t[0] += 64;
          ha_blake2s_compress (ctx, ctx->buf);
          ctx->buflen = 0;
        }
    }
}

HA_PUBFUN void
ha_blake2s_final (ha_blake2s_context *ctx, ha_digest_t digest,
                  size_t digestlen)
{
  ctx->h[0] ^= (uint32_t)digestlen | (1U << 16) | (1U << 24);
  ctx->outlen = digestlen;

  ctx->t[0] += ctx->buflen;
  ctx->f[0] = ~0U;
  memset (ctx->buf + ctx->buflen, 0, 64 - ctx->buflen);
  ha_blake2s_compress (ctx, ctx->buf);

#ifdef HA_ONLY_LE
  memcpy (digest, ctx->h, ctx->outlen);
#else
  for (size_t i = 0; i < digestlen / 4; i++)
    store_le32 (digest + i * 4, ctx->h[i]);

  if (digestlen % 8 != 0)
    {
      uint64_t word = ctx->h[digestlen / 4];
      for (size_t j = 0; j < digestlen % 4; j++)
        digest[(digestlen / 4) * 4 + j] = (word >> (4 * j)) & 0xFF;
    }
#endif
}

HA_PUBFUN void
ha_blake2s_hash (ha_inbuf_t data, size_t len, ha_digest_t digest,
                 size_t digestlen)
{
  ha_blake2s_context ctx;
  ha_blake2s_init (&ctx);
  ha_blake2s_update (&ctx, data, len);
  ha_blake2s_final (&ctx, digest, digestlen);
}
