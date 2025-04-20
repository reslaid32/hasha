#define HA_BUILD

#include "../include/hasha/blake2s.h"

#include "./endian.h"

static const uint32_t blake2s_iv[8]
    = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

static const uint8_t blake2s_sigma[10][16]
    = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

HA_PRVFUN void
ha_blake2s_compress (ha_blake2s_context *ctx, const uint8_t block[64])
{
  uint32_t v[16], m[16];
  int i;

  for (i = 0; i < 8; i++)
    {
      v[i] = ctx->h[i];
      v[i + 8] = blake2s_iv[i];
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

  ha_primitive_blake32_round (blake2s_sigma, 0);
  ha_primitive_blake32_round (blake2s_sigma, 1);
  ha_primitive_blake32_round (blake2s_sigma, 2);
  ha_primitive_blake32_round (blake2s_sigma, 3);
  ha_primitive_blake32_round (blake2s_sigma, 4);
  ha_primitive_blake32_round (blake2s_sigma, 5);
  ha_primitive_blake32_round (blake2s_sigma, 6);
  ha_primitive_blake32_round (blake2s_sigma, 7);
  ha_primitive_blake32_round (blake2s_sigma, 8);
  ha_primitive_blake32_round (blake2s_sigma, 9);

  for (i = 0; i < 8; i++)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

HA_PUBFUN void
ha_blake2s_init (ha_blake2s_context *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  memcpy (ctx->h, blake2s_iv, sizeof (ctx->h));
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
