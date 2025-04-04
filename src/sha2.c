#define HA_BUILD

#include "../include/hasha/sha2.h"

#include "../include/hasha/sha2_k.h"

HA_PUBFUN void ha_sha2_224_transform(ha_sha2_224_context *ctx,
                                     const uint8_t *block)
{
  ha_sha2_256_transform((ha_sha2_256_context *)ctx, block);
}

HA_PUBFUN void ha_sha2_224_init(ha_sha2_224_context *ctx)
{
  memcpy(ctx->state, HA_SHA2_224_H0, sizeof(HA_SHA2_224_H0));
  ctx->bit_count = 0;
  memset(ctx->buffer, 0, HA_SHA2_224_BLOCK_SIZE);
}

HA_PUBFUN void ha_sha2_224_update(ha_sha2_224_context *ctx,
                                  ha_inbuf_t data, size_t length)
{
  ha_sha2_256_update((ha_sha2_256_context *)ctx, data, length);
}

HA_PUBFUN void ha_sha2_224_final(ha_sha2_224_context *ctx,
                                 ha_digest_t digest)
{
  uint8_t full_digest[HA_SHA2_256_DIGEST_SIZE];
  ha_sha2_256_final((ha_sha2_256_context *)ctx, full_digest);

  memcpy(digest, full_digest, HA_SHA2_224_DIGEST_SIZE);
}

HA_PUBFUN void ha_sha2_224_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest)
{
  ha_sha2_224_context ctx;
  ha_sha2_224_init(&ctx);
  ha_sha2_224_update(&ctx, data, length);
  ha_sha2_224_final(&ctx, digest);
}

HA_PUBFUN void ha_sha2_256_transform(ha_sha2_256_context *ctx,
                                     const uint8_t *block)
{
  uint32_t W[64];
  uint32_t a, b, c, d, e, f, g, h;

  for (int t = 0; t < 16; ++t)
  {
    W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) |
           (block[t * 4 + 2] << 8) | block[t * 4 + 3];
  }
  for (int t = 16; t < 64; ++t)
  {
    W[t] = ha_primitive_sigma1_32(W[t - 2]) + W[t - 7] +
           ha_primitive_sigma0_32(W[t - 15]) + W[t - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (int t = 0; t < 64; ++t)
  {
    uint32_t T1 = h + ha_primitive_Sigma1_32(e) +
                  ha_primitive_ch(e, f, g) + HA_SHA2_256_K[t] + W[t];
    uint32_t T2 = ha_primitive_Sigma0_32(a) + ha_primitive_maj(a, b, c);
    h           = g;
    g           = f;
    f           = e;
    e           = d + T1;
    d           = c;
    c           = b;
    b           = a;
    a           = T1 + T2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

HA_PUBFUN void ha_sha2_256_init(ha_sha2_256_context *ctx)
{
  // ctx->state[0] = 0x6a09e667;
  // ctx->state[1] = 0xbb67ae85;
  // ctx->state[2] = 0x3c6ef372;
  // ctx->state[3] = 0xa54ff53a;
  // ctx->state[4] = 0x510e527f;
  // ctx->state[5] = 0x9b05688c;
  // ctx->state[6] = 0x1f83d9ab;
  // ctx->state[7] = 0x5be0cd19;
  memcpy(ctx->state, HA_SHA2_256_H0, sizeof(HA_SHA2_256_H0));
  ctx->bit_count = 0;
  memset(ctx->buffer, 0, HA_SHA2_256_BLOCK_SIZE);
}

HA_PUBFUN void ha_sha2_256_update(ha_sha2_256_context *ctx,
                                  ha_inbuf_t data, size_t length)
{
  size_t buffer_fill = ctx->bit_count / 8 % HA_SHA2_256_BLOCK_SIZE;
  ctx->bit_count += (uint64_t)length * 8;

  size_t offset = 0;
  while (length > 0)
  {
    size_t space     = HA_SHA2_256_BLOCK_SIZE - buffer_fill;
    size_t copy_size = length < space ? length : space;

    memcpy(ctx->buffer + buffer_fill, data + offset, copy_size);
    buffer_fill += copy_size;
    offset += copy_size;
    length -= copy_size;

    if (buffer_fill == HA_SHA2_256_BLOCK_SIZE)
    {
      ha_sha2_256_transform(ctx, ctx->buffer);
      buffer_fill = 0;
    }
  }
}

HA_PUBFUN void ha_sha2_256_final(ha_sha2_256_context *ctx,
                                 ha_digest_t digest)
{
  size_t buffer_fill         = ctx->bit_count / 8 % HA_SHA2_256_BLOCK_SIZE;
  ctx->buffer[buffer_fill++] = 0x80;

  if (buffer_fill > HA_SHA2_256_BLOCK_SIZE - 8)
  {
    memset(ctx->buffer + buffer_fill, 0,
           HA_SHA2_256_BLOCK_SIZE - buffer_fill);
    ha_sha2_256_transform(ctx, ctx->buffer);
    buffer_fill = 0;
  }

  memset(ctx->buffer + buffer_fill, 0,
         HA_SHA2_256_BLOCK_SIZE - buffer_fill - 8);
  for (int i = 0; i < 8; ++i)
  {
    ctx->buffer[HA_SHA2_256_BLOCK_SIZE - 1 - i] =
        (ctx->bit_count >> (8 * i)) & 0xff;
  }
  ha_sha2_256_transform(ctx, ctx->buffer);

  for (int i = 0; i < 8; ++i)
  {
    digest[i * 4]     = (ctx->state[i] >> 24) & 0xff;
    digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
    digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff;
    digest[i * 4 + 3] = ctx->state[i] & 0xff;
  }
}

HA_PUBFUN void ha_sha2_256_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest)
{
  ha_sha2_256_context ctx;
  ha_sha2_256_init(&ctx);
  ha_sha2_256_update(&ctx, data, length);
  ha_sha2_256_final(&ctx, digest);
}

HA_PUBFUN void ha_sha2_384_transform(ha_sha2_384_context *ctx,
                                     const uint8_t *block)
{
  ha_sha2_512_transform((ha_sha2_512_context *)ctx, block);
}

HA_PUBFUN void ha_sha2_384_init(ha_sha2_384_context *ctx)
{
  memcpy(ctx->state, HA_SHA2_384_H0, sizeof(HA_SHA2_384_H0));
  ctx->bit_count[0] = ctx->bit_count[1] = 0;
  memset(ctx->buffer, 0, HA_SHA2_384_BLOCK_SIZE);
}

HA_PUBFUN void ha_sha2_384_update(ha_sha2_384_context *ctx,
                                  ha_inbuf_t data, size_t length)
{
  ha_sha2_512_update((ha_sha2_512_context *)ctx, data, length);
}

HA_PUBFUN void ha_sha2_384_final(ha_sha2_384_context *ctx,
                                 ha_digest_t digest)
{
  uint8_t full_digest[HA_SHA2_512_DIGEST_SIZE];
  ha_sha2_512_final((ha_sha2_512_context *)ctx, full_digest);

  memcpy(digest, full_digest, HA_SHA2_384_DIGEST_SIZE);
}

HA_PUBFUN void ha_sha2_384_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest)
{
  ha_sha2_384_context ctx;
  ha_sha2_384_init(&ctx);
  ha_sha2_384_update(&ctx, data, length);
  ha_sha2_384_final(&ctx, digest);
}

HA_PUBFUN void ha_sha2_512_transform(ha_sha2_512_context *ctx,
                                     const uint8_t *block)
{
  uint64_t m[80];
  uint64_t a, b, c, d, e, f, g, h;
  uint64_t T1, T2;

  for (int i = 0; i < 16; ++i)
  {
    m[i] = ((uint64_t)block[i * 8] << 56) |
           ((uint64_t)block[i * 8 + 1] << 48) |
           ((uint64_t)block[i * 8 + 2] << 40) |
           ((uint64_t)block[i * 8 + 3] << 32) |
           ((uint64_t)block[i * 8 + 4] << 24) |
           ((uint64_t)block[i * 8 + 5] << 16) |
           ((uint64_t)block[i * 8 + 6] << 8) |
           ((uint64_t)block[i * 8 + 7]);
  }

  for (int i = 16; i < 80; ++i)
  {
    m[i] = ha_primitive_sigma1_64(m[i - 2]) + m[i - 7] +
           ha_primitive_sigma0_64(m[i - 15]) + m[i - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (int i = 0; i < 80; ++i)
  {
    T1 = h + ha_primitive_Sigma1_64(e) + ha_primitive_ch(e, f, g) +
         HA_SHA2_512_K[i] + m[i];
    T2 = ha_primitive_Sigma0_64(a) + ha_primitive_maj(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

HA_PUBFUN void ha_sha2_512_init(ha_sha2_512_context *ctx)
{
  // ctx->state[0] = 0x6a09e667f3bcc908ULL;
  // ctx->state[1] = 0xbb67ae8584caa73bULL;
  // ctx->state[2] = 0x3c6ef372fe94f82bULL;
  // ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  // ctx->state[4] = 0x510e527fade682d1ULL;
  // ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  // ctx->state[6] = 0x1f83d9abfb41bd6bULL;
  // ctx->state[7] = 0x5be0cd19137e2179ULL;
  memcpy(ctx->state, HA_SHA2_512_H0, sizeof(HA_SHA2_512_H0));
  ctx->bit_count = 0;
  memset(ctx->buffer, 0, HA_SHA2_512_BLOCK_SIZE);
}

HA_PUBFUN void ha_sha2_512_update(ha_sha2_512_context *ctx,
                                  ha_inbuf_t data, size_t len)
{
  size_t buffer_fill = (ctx->bit_count / 8) % HA_SHA2_512_BLOCK_SIZE;
  ctx->bit_count += (uint64_t)len * 8;

  size_t offset = 0;
  while (len > 0)
  {
    size_t space_in_buffer = HA_SHA2_512_BLOCK_SIZE - buffer_fill;
    size_t to_copy = (len < space_in_buffer) ? len : space_in_buffer;
    memcpy(ctx->buffer + buffer_fill, data + offset, to_copy);
    buffer_fill += to_copy;
    offset += to_copy;
    len -= to_copy;

    if (buffer_fill == HA_SHA2_512_BLOCK_SIZE)
    {
      ha_sha2_512_transform(ctx, ctx->buffer);
      buffer_fill = 0;
    }
  }
}

HA_PUBFUN void ha_sha2_512_final(ha_sha2_512_context *ctx,
                                 ha_digest_t digest)
{
  size_t buffer_fill = (ctx->bit_count / 8) % HA_SHA2_512_BLOCK_SIZE;
  ctx->buffer[buffer_fill++] = 0x80;

  if (buffer_fill > HA_SHA2_512_BLOCK_SIZE - 16)
  {
    memset(ctx->buffer + buffer_fill, 0,
           HA_SHA2_512_BLOCK_SIZE - buffer_fill);
    ha_sha2_512_transform(ctx, ctx->buffer);
    buffer_fill = 0;
  }

  memset(ctx->buffer + buffer_fill, 0,
         HA_SHA2_512_BLOCK_SIZE - buffer_fill - 16);
  for (int i = 0; i < 8; ++i)
  {
    ctx->buffer[HA_SHA2_512_BLOCK_SIZE - 1 - i] =
        (ctx->bit_count >> (8 * i)) & 0xff;
  }

  ha_sha2_512_transform(ctx, ctx->buffer);

  for (int i = 0; i < 8; ++i)
  {
    digest[i * 8 + 0] = (ctx->state[i] >> 56) & 0xff;
    digest[i * 8 + 1] = (ctx->state[i] >> 48) & 0xff;
    digest[i * 8 + 2] = (ctx->state[i] >> 40) & 0xff;
    digest[i * 8 + 3] = (ctx->state[i] >> 32) & 0xff;
    digest[i * 8 + 4] = (ctx->state[i] >> 24) & 0xff;
    digest[i * 8 + 5] = (ctx->state[i] >> 16) & 0xff;
    digest[i * 8 + 6] = (ctx->state[i] >> 8) & 0xff;
    digest[i * 8 + 7] = ctx->state[i] & 0xff;
  }
}

HA_PUBFUN void ha_sha2_512_hash(ha_inbuf_t data, size_t length,
                                ha_digest_t digest)
{
  ha_sha2_512_context ctx;
  ha_sha2_512_init(&ctx);
  ha_sha2_512_update(&ctx, data, length);
  ha_sha2_512_final(&ctx, digest);
}

HA_PUBFUN void ha_sha2_512_224_transform(ha_sha2_512_224_context *ctx,
                                         const uint8_t *block)
{
  ha_sha2_512_transform((ha_sha2_512_context *)ctx, block);
}

HA_PUBFUN void ha_sha2_512_224_init(ha_sha2_512_224_context *ctx)
{
  memcpy(ctx->state, HA_SHA2_512_224_H0, sizeof(HA_SHA2_512_224_H0));
  ctx->bit_count = 0;
  memset(ctx->buffer, 0, HA_SHA2_512_BLOCK_SIZE);
}

HA_PUBFUN void ha_sha2_512_224_update(ha_sha2_512_224_context *ctx,
                                      ha_inbuf_t data, size_t length)
{
  ha_sha2_512_update((ha_sha2_512_context *)ctx, data, length);
}

HA_PUBFUN void ha_sha2_512_224_final(ha_sha2_512_224_context *ctx,
                                     ha_digest_t digest)
{
  uint8_t full_digest[HA_SHA2_512_DIGEST_SIZE];
  ha_sha2_512_final((ha_sha2_512_context *)ctx, full_digest);

  memcpy(digest, full_digest, HA_SHA2_512_224_DIGEST_SIZE);
}

HA_PUBFUN void ha_sha2_512_224_hash(ha_inbuf_t data, size_t length,
                                    ha_digest_t digest)
{
  ha_sha2_512_224_context ctx;
  ha_sha2_512_224_init(&ctx);
  ha_sha2_512_224_update(&ctx, data, length);
  ha_sha2_512_224_final(&ctx, digest);
}

HA_PUBFUN void ha_sha2_512_256_transform(ha_sha2_512_256_context *ctx,
                                         const uint8_t *block)
{
  ha_sha2_512_transform((ha_sha2_512_context *)ctx, block);
}

HA_PUBFUN void ha_sha2_512_256_init(ha_sha2_512_256_context *ctx)
{
  memcpy(ctx->state, HA_SHA2_512_256_H0, sizeof(HA_SHA2_512_256_H0));
  ctx->bit_count = 0;
  memset(ctx->buffer, 0, HA_SHA2_512_BLOCK_SIZE);
}

HA_PUBFUN void ha_sha2_512_256_update(ha_sha2_512_256_context *ctx,
                                      ha_inbuf_t data, size_t length)
{
  ha_sha2_512_update((ha_sha2_512_context *)ctx, data, length);
}

HA_PUBFUN void ha_sha2_512_256_final(ha_sha2_512_256_context *ctx,
                                     ha_digest_t digest)
{
  uint8_t full_digest[HA_SHA2_512_DIGEST_SIZE];
  ha_sha2_512_final((ha_sha2_512_context *)ctx, full_digest);

  memcpy(digest, full_digest, HA_SHA2_512_256_DIGEST_SIZE);
}

HA_PUBFUN void ha_sha2_512_256_hash(ha_inbuf_t data, size_t length,
                                    ha_digest_t digest)
{
  ha_sha2_512_256_context ctx;
  ha_sha2_512_256_init(&ctx);
  ha_sha2_512_256_update(&ctx, data, length);
  ha_sha2_512_256_final(&ctx, digest);
}