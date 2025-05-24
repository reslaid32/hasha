#define HA_BUILD

#include "../include/hasha/blake2b.h"
#include "../include/hasha/blake2b_k.h"

#include "./endian.h"

HA_PRVFUN void
ha_blake2b_compress (ha_blake2b_context *ctx, const uint8_t block[128])
{
  uint64_t v[16], m[16];
  int i;

  for (i = 0; i < 8; i++)
    {
      v[i] = ctx->h[i];
      v[i + 8] = HA_BLAKE2B_H0[i];
    }

  v[12] ^= (ctx->t[0]);
  v[13] ^= (ctx->t[1]);
  v[14] ^= (ctx->f[0]);
  v[15] ^= (ctx->f[1]);

#ifdef HA_ONLY_LE
  for (i = 0; i < 16; i++)
    m[i] = (((uint64_t *)block)[i]);
#else
  for (i = 0; i < 16; i++)
    {
      uint64_t word;
      memcpy (&word, block + i * 8, 8);
      m[i] = le64_to_cpu (word);
    }
#endif

  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 0);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 1);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 2);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 3);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 4);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 5);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 6);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 7);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 8);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 9);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 10);
  ha_primitive_blake64_round (HA_BLAKE2B_SIGMA, 11);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

HA_PUBFUN void
ha_blake2b_init (ha_blake2b_context *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  memcpy (ctx->h, HA_BLAKE2B_H0, sizeof (ctx->h));
}

HA_PUBFUN void
ha_blake2b_update (ha_blake2b_context *ctx, ha_inbuf_t data, size_t len)
{
  while (len > 0)
    {
      size_t fill = 128 - ctx->buflen;
      size_t to_copy = len < fill ? len : fill;
      memcpy (ctx->buf + ctx->buflen, data, to_copy);
      ctx->buflen += to_copy;
      data += to_copy;
      len -= to_copy;

      if (ctx->buflen == 128)
        {
          ctx->t[0] += 128;
          ha_blake2b_compress (ctx, ctx->buf);
          ctx->buflen = 0;
        }
    }
}

HA_PUBFUN void
ha_blake2b_final (ha_blake2b_context *ctx, ha_digest_t digest,
                  size_t digestlen)
{
  ctx->h[0] ^= (uint64_t)digestlen | (1ULL << 16) | (1ULL << 24);
  ctx->outlen = digestlen;

  ctx->t[0] += ctx->buflen;
  ctx->f[0] = ~0ULL;
  memset (ctx->buf + ctx->buflen, 0, 128 - ctx->buflen);
  ha_blake2b_compress (ctx, ctx->buf);

#ifdef HA_ONLY_LE
  memcpy (digest, ctx->h, ctx->outlen);
#else
  for (size_t i = 0; i < digestlen / 8; i++)
    store_le64 (digest + i * 8, ctx->h[i]);

  if (digestlen % 8 != 0)
    {
      uint64_t word = ctx->h[digestlen / 8];
      for (size_t j = 0; j < digestlen % 8; j++)
        digest[(digestlen / 8) * 8 + j] = (word >> (8 * j)) & 0xFF;
    }
#endif
}

HA_PUBFUN void
ha_blake2b_hash (ha_inbuf_t data, size_t len, ha_digest_t digest,
                 size_t digestlen)
{
  ha_blake2b_context ctx;
  ha_blake2b_init (&ctx);
  ha_blake2b_update (&ctx, data, len);
  ha_blake2b_final (&ctx, digest, digestlen);
}
