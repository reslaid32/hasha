
#define HASHA_LIBRARY_BUILD

#include "../include/hasha/blake2s.h"

static const uint32_t blake2s_iv[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                       0xA54FF53A, 0x510E527F, 0x9B05688C,
                                       0x1F83D9AB, 0x5BE0CD19};

static const uint8_t blake2s_sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

HASHA_PRIVATE_FUNC void ha_blake2s_compress(ha_blake2s_context *ctx,
                                            const uint8_t block[64])
{
  uint32_t v[16], m[16];
  int i;

  for (i = 0; i < 8; i++)
  {
    v[i]     = ctx->h[i];
    v[i + 8] = blake2s_iv[i];
  }

  v[12] ^= ctx->t[0];
  v[13] ^= ctx->t[1];
  v[14] ^= ctx->f[0];
  v[15] ^= ctx->f[1];

  for (i = 0; i < 16; i++) m[i] = ((uint32_t *)block)[i];

  for (i = 0; i < 10; i++)
  {
#define G(r, i, a, b, c, d)                \
  a += b + m[blake2s_sigma[r][2 * i + 0]]; \
  d ^= a;                                  \
  d = (d >> 16) | (d << 16);               \
  c += d;                                  \
  b ^= c;                                  \
  b = (b >> 12) | (b << 20);               \
  a += b + m[blake2s_sigma[r][2 * i + 1]]; \
  d ^= a;                                  \
  d = (d >> 8) | (d << 24);                \
  c += d;                                  \
  b ^= c;                                  \
  b = (b >> 7) | (b << 25);

    G(i, 0, v[0], v[4], v[8], v[12]);
    G(i, 1, v[1], v[5], v[9], v[13]);
    G(i, 2, v[2], v[6], v[10], v[14]);
    G(i, 3, v[3], v[7], v[11], v[15]);
    G(i, 4, v[0], v[5], v[10], v[15]);
    G(i, 5, v[1], v[6], v[11], v[12]);
    G(i, 6, v[2], v[7], v[8], v[13]);
    G(i, 7, v[3], v[4], v[9], v[14]);
  }

  for (i = 0; i < 8; i++) ctx->h[i] ^= v[i] ^ v[i + 8];
}

HASHA_PUBLIC_FUNC void ha_blake2s_init(ha_blake2s_context *ctx,
                                       size_t outlen)
{
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->h, blake2s_iv, sizeof(ctx->h));
  ctx->h[0] ^= (uint32_t)outlen | (1U << 16) | (1U << 24);
  ctx->outlen = outlen;
}

HASHA_PUBLIC_FUNC void ha_blake2s_update(ha_blake2s_context *ctx,
                                         const uint8_t *data, size_t len)
{
  while (len > 0)
  {
    size_t fill    = 64 - ctx->buflen;
    size_t to_copy = len < fill ? len : fill;
    memcpy(ctx->buf + ctx->buflen, data, to_copy);
    ctx->buflen += to_copy;
    data += to_copy;
    len -= to_copy;

    if (ctx->buflen == 64)
    {
      ctx->t[0] += 64;
      ha_blake2s_compress(ctx, ctx->buf);
      ctx->buflen = 0;
    }
  }
}

HASHA_PUBLIC_FUNC void ha_blake2s_final(ha_blake2s_context *ctx,
                                        uint8_t *digest)
{
  ctx->t[0] += ctx->buflen;
  ctx->f[0] = ~0U;
  memset(ctx->buf + ctx->buflen, 0, 64 - ctx->buflen);
  ha_blake2s_compress(ctx, ctx->buf);

  memcpy(digest, ctx->h, ctx->outlen);
}

HASHA_PUBLIC_FUNC void ha_blake2s_hash(const uint8_t *data, size_t len,
                                       uint8_t *digest, size_t digestlen)
{
  ha_blake2s_context ctx;
  ha_blake2s_init(&ctx, digestlen);
  ha_blake2s_update(&ctx, data, len);
  ha_blake2s_final(&ctx, digest);
}
