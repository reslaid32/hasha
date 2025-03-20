#define HASHA_LIBRARY_BUILD

#include "../include/hasha/blake2b.h"

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static const uint8_t blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

HASHA_PRIVATE_FUNC void ha_blake2b_compress(ha_blake2b_context *ctx,
                                            const uint8_t block[128])
{
  uint64_t v[16], m[16];
  int i;

  for (i = 0; i < 8; i++)
  {
    v[i]     = ctx->h[i];
    v[i + 8] = blake2b_iv[i];
  }

  v[12] ^= __le32(ctx->t[0]);
  v[13] ^= __le32(ctx->t[1]);
  v[14] ^= __le32(ctx->f[0]);
  v[15] ^= __le32(ctx->f[1]);

  for (i = 0; i < 16; i++) m[i] = __le64(((uint64_t *)block)[i]);

  for (i = 0; i < 12; i++)
  {
#define G(r, i, a, b, c, d)                \
  a += b + m[blake2b_sigma[r][2 * i + 0]]; \
  d ^= a;                                  \
  d = (d >> 32) | (d << 32);               \
  c += d;                                  \
  b ^= c;                                  \
  b = (b >> 24) | (b << 40);               \
  a += b + m[blake2b_sigma[r][2 * i + 1]]; \
  d ^= a;                                  \
  d = (d >> 16) | (d << 48);               \
  c += d;                                  \
  b ^= c;                                  \
  b = (b >> 63) | (b << 1);

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

HASHA_PUBLIC_FUNC void ha_blake2b_init(ha_blake2b_context *ctx,
                                       size_t outlen)
{
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->h, blake2b_iv, sizeof(ctx->h));
  ctx->h[0] ^= (uint64_t)outlen | (1ULL << 16) | (1ULL << 24);
  ctx->outlen = outlen;
}

HASHA_PUBLIC_FUNC void ha_blake2b_update(ha_blake2b_context *ctx,
                                         const uint8_t *data, size_t len)
{
  while (len > 0)
  {
    size_t fill    = 128 - ctx->buflen;
    size_t to_copy = len < fill ? len : fill;
    memcpy(ctx->buf + ctx->buflen, data, to_copy);
    ctx->buflen += to_copy;
    data += to_copy;
    len -= to_copy;

    if (ctx->buflen == 128)
    {
      ctx->t[0] += 128;
      ha_blake2b_compress(ctx, ctx->buf);
      ctx->buflen = 0;
    }
  }
}

HASHA_PUBLIC_FUNC void ha_blake2b_final(ha_blake2b_context *ctx,
                                        uint8_t *digest)
{
  ctx->t[0] += ctx->buflen;
  ctx->f[0] = ~0ULL;
  memset(ctx->buf + ctx->buflen, 0, 128 - ctx->buflen);
  ha_blake2b_compress(ctx, ctx->buf);

  memcpy(digest, ctx->h, ctx->outlen);
}

HASHA_PUBLIC_FUNC void ha_blake2b_hash(const uint8_t *data, size_t len,
                                       uint8_t *digest, size_t digestlen)
{
  ha_blake2b_context ctx;
  ha_blake2b_init(&ctx, digestlen);
  ha_blake2b_update(&ctx, data, len);
  ha_blake2b_final(&ctx, digest);
}
