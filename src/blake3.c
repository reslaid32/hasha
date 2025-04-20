#define HA_BUILD

#include "../include/hasha/blake3.h"

#define BLAKE3_FLAG_CHUNK_START (1u << 0)
#define BLAKE3_FLAG_CHUNK_END (1u << 1)
#define BLAKE3_FLAG_PARENT (1u << 2)
#define BLAKE3_FLAG_ROOT (1u << 3)

static const uint32_t blake3_iv[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const uint8_t blake3_sigma[7][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
  { 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
  { 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
  { 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
  { 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
  { 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

HA_PRVFUN void
blake3_compress (uint32_t *outbuf, const uint32_t m[static 16],
                 const uint32_t h[static 8], uint64_t t, uint32_t b,
                 uint32_t d)
{
  uint32_t v[16] = { h[0],
                     h[1],
                     h[2],
                     h[3],
                     h[4],
                     h[5],
                     h[6],
                     h[7],
                     blake3_iv[0],
                     blake3_iv[1],
                     blake3_iv[2],
                     blake3_iv[3],
                     t,
                     t >> 32,
                     b,
                     d };
  uint32_t i;

  ha_primitive_blake32_round (blake3_sigma, 0);
  ha_primitive_blake32_round (blake3_sigma, 1);
  ha_primitive_blake32_round (blake3_sigma, 2);
  ha_primitive_blake32_round (blake3_sigma, 3);
  ha_primitive_blake32_round (blake3_sigma, 4);
  ha_primitive_blake32_round (blake3_sigma, 5);
  ha_primitive_blake32_round (blake3_sigma, 6);

  if (d & BLAKE3_FLAG_ROOT)
    for (i = 8; i < 16; ++i)
      outbuf[i] = v[i] ^ h[i - 8];
  for (i = 0; i < 8; ++i)
    outbuf[i] = v[i] ^ v[i + 8];
}

HA_PRVFUN void
blake3_load (uint32_t d[static 16], const uint8_t s[static 64])
{
  uint32_t *end;

  for (end = d + 16; d < end; ++d, s += 4)
    {
      *d = (uint32_t)s[0] | (uint32_t)s[1] << 8 | (uint32_t)s[2] << 16
           | (uint32_t)s[3] << 24;
    }
}

HA_PRVFUN void
blake3_block (ha_blake3_context *ctx, const unsigned char *buf)
{
  uint32_t m[16], flags, *cv = ctx->cv;
  uint64_t t;

  flags = 0;
  switch (ctx->block)
    {
    case 0:
      flags |= BLAKE3_FLAG_CHUNK_START;
      break;
    case 15:
      flags |= BLAKE3_FLAG_CHUNK_END;
      break;
    }
  blake3_load (m, buf);
  blake3_compress (cv, m, cv, ctx->chunk, 64, flags);
  if (++ctx->block == 16)
    {
      ctx->block = 0;
      for (t = ++ctx->chunk; (t & 1) == 0; t >>= 1)
        {
          cv -= 8;
          blake3_compress (cv, cv, blake3_iv, 0, 64, BLAKE3_FLAG_PARENT);
        }
      cv += 8;
      memcpy (cv, blake3_iv, sizeof (blake3_iv));
    }
  ctx->cv = cv;
}

HA_PUBFUN void
ha_blake3_init (ha_blake3_context *ctx)
{
  ctx->bytes = ctx->block = ctx->chunk = 0;
  ctx->cv = ctx->cv_buf;
  memcpy (ctx->cv, blake3_iv, sizeof (blake3_iv));
}

HA_PUBFUN void
ha_blake3_update (ha_blake3_context *ctx, ha_inbuf_t data, size_t length)
{
  const uint8_t *pos = data;
  size_t n;

  if (ctx->bytes)
    {
      n = 64 - ctx->bytes;
      if (length < n)
        n = length;
      memcpy (ctx->input + ctx->bytes, pos, n);
      pos += n, length -= n;
      ctx->bytes += n;
      if (!length)
        return;
      blake3_block (ctx, ctx->input);
    }

  for (; length > 64; pos += 64, length -= 64)
    blake3_block (ctx, pos);
  ctx->bytes = length;
  memcpy (ctx->input, pos, length);
}

HA_PUBFUN void
ha_blake3_final (ha_blake3_context *ctx, ha_digest_t digest, size_t length)
{
  uint32_t f, b, x = 0, *in, *cv, m[16], root[16];
  size_t i;

  cv = ctx->cv;
  memset (ctx->input + ctx->bytes, 0, 64 - ctx->bytes);
  blake3_load (m, ctx->input);
  f = BLAKE3_FLAG_CHUNK_END;
  if (ctx->block == 0)
    f |= BLAKE3_FLAG_CHUNK_START;
  if (cv == ctx->cv_buf)
    {
      b = ctx->bytes;
      in = m;
    }
  else
    {
      blake3_compress (cv, m, cv, ctx->chunk, ctx->bytes, f);
      f = BLAKE3_FLAG_PARENT;
      while ((cv -= 8) != ctx->cv_buf)
        blake3_compress (cv, cv, blake3_iv, 0, 64, f);
      b = 64;
      in = cv;
      cv = (uint32_t *)blake3_iv;
    }
  f |= BLAKE3_FLAG_ROOT;
  for (i = 0; i < length; ++i, ++digest, x >>= 8)
    {
      if ((i & 63) == 0)
        blake3_compress (root, in, cv, i >> 6, b, f);
      if ((i & 3) == 0)
        x = root[i >> 2 & 15];
      *digest = x & 0xff;
    }
}

HA_PUBFUN void
ha_blake3_hash (ha_inbuf_t data, size_t length, ha_digest_t digest,
                size_t digest_length)
{
  ha_blake3_context ctx;
  ha_blake3_init (&ctx);
  ha_blake3_update (&ctx, data, length);
  ha_blake3_final (&ctx, digest, digest_length);
}