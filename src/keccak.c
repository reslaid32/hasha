#define HASHA_LIBRARY_BUILD

#include "../include/hasha/keccak.h"

#include "../include/hasha/keccakf1600.h"

HASHA_PUBLIC_FUNC void ha_keccak_224_init(ha_keccak_224_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = KECCAK_224_RATE;
  ctx->capacity      = 200 - KECCAK_224_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = KECCAK_224_RATE;
}

HASHA_PUBLIC_FUNC void ha_keccak_224_absorb(ha_keccak_224_context *ctx,
                                            const uint8_t *data,
                                            size_t length)
{
  size_t i = 0;
  while (i < length)
  {
    size_t absorb_bytes = ctx->rate - ctx->absorb_index;
    if (absorb_bytes > length - i) { absorb_bytes = length - i; }
    for (size_t j = 0; j < absorb_bytes; ++j)
    {
      ctx->state[ctx->absorb_index + j] ^= data[i + j];
    }
    ctx->absorb_index += absorb_bytes;
    i += absorb_bytes;

    if (ctx->absorb_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->absorb_index = 0;
    }
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_224_final(ha_keccak_224_context *ctx)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void ha_keccak_224_squeeze(ha_keccak_224_context *ctx,
                                             uint8_t *digest)
{
  size_t i = 0;
  while (i < KECCAK_224_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_224_hash(const uint8_t *data,
                                          size_t length, uint8_t *digest)
{
  ha_keccak_224_context ctx;
  ha_keccak_224_init(&ctx);
  ha_keccak_224_absorb(&ctx, data, length);
  ha_keccak_224_final(&ctx);
  ha_keccak_224_squeeze(&ctx, digest);
}

HASHA_PUBLIC_FUNC void ha_keccak_256_init(ha_keccak_256_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = KECCAK_256_RATE;
  ctx->capacity      = 200 - KECCAK_256_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = KECCAK_256_RATE;
}

HASHA_PUBLIC_FUNC void ha_keccak_256_absorb(ha_keccak_256_context *ctx,
                                            const uint8_t *data,
                                            size_t length)
{
  size_t i = 0;
  while (i < length)
  {
    size_t absorb_bytes = ctx->rate - ctx->absorb_index;
    if (absorb_bytes > length - i) { absorb_bytes = length - i; }
    for (size_t j = 0; j < absorb_bytes; ++j)
    {
      ctx->state[ctx->absorb_index + j] ^= data[i + j];
    }
    ctx->absorb_index += absorb_bytes;
    i += absorb_bytes;

    if (ctx->absorb_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->absorb_index = 0;
    }
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_256_final(ha_keccak_256_context *ctx)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void ha_keccak_256_squeeze(ha_keccak_256_context *ctx,
                                             uint8_t *digest)
{
  size_t i = 0;
  while (i < KECCAK_256_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_256_hash(const uint8_t *data,
                                          size_t length, uint8_t *digest)
{
  ha_keccak_256_context ctx;
  ha_keccak_256_init(&ctx);
  ha_keccak_256_absorb(&ctx, data, length);
  ha_keccak_256_final(&ctx);
  ha_keccak_256_squeeze(&ctx, digest);
}

HASHA_PUBLIC_FUNC void ha_keccak_384_init(ha_keccak_384_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = KECCAK_384_RATE;
  ctx->capacity      = 200 - KECCAK_384_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = KECCAK_384_RATE;
}

HASHA_PUBLIC_FUNC void ha_keccak_384_absorb(ha_keccak_384_context *ctx,
                                            const uint8_t *data,
                                            size_t length)
{
  size_t i = 0;
  while (i < length)
  {
    size_t absorb_bytes = ctx->rate - ctx->absorb_index;
    if (absorb_bytes > length - i) { absorb_bytes = length - i; }
    for (size_t j = 0; j < absorb_bytes; ++j)
    {
      ctx->state[ctx->absorb_index + j] ^= data[i + j];
    }
    ctx->absorb_index += absorb_bytes;
    i += absorb_bytes;

    if (ctx->absorb_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->absorb_index = 0;
    }
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_384_final(ha_keccak_384_context *ctx)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void ha_keccak_384_squeeze(ha_keccak_384_context *ctx,
                                             uint8_t *digest)
{
  size_t i = 0;
  while (i < KECCAK_384_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_384_hash(const uint8_t *data,
                                          size_t length, uint8_t *digest)
{
  ha_keccak_384_context ctx;
  ha_keccak_384_init(&ctx);
  ha_keccak_384_absorb(&ctx, data, length);
  ha_keccak_384_final(&ctx);
  ha_keccak_384_squeeze(&ctx, digest);
}

HASHA_PUBLIC_FUNC void ha_keccak_512_init(ha_keccak_512_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = KECCAK_512_RATE;
  ctx->capacity      = 200 - KECCAK_512_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = KECCAK_512_RATE;
}

HASHA_PUBLIC_FUNC void ha_keccak_512_absorb(ha_keccak_512_context *ctx,
                                            const uint8_t *data,
                                            size_t length)
{
  size_t i = 0;
  while (i < length)
  {
    size_t absorb_bytes = ctx->rate - ctx->absorb_index;
    if (absorb_bytes > length - i) { absorb_bytes = length - i; }
    for (size_t j = 0; j < absorb_bytes; ++j)
    {
      ctx->state[ctx->absorb_index + j] ^= data[i + j];
    }
    ctx->absorb_index += absorb_bytes;
    i += absorb_bytes;

    if (ctx->absorb_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->absorb_index = 0;
    }
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_512_final(ha_keccak_512_context *ctx)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void ha_keccak_512_squeeze(ha_keccak_512_context *ctx,
                                             uint8_t *digest)
{
  size_t i = 0;
  while (i < KECCAK_512_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_keccak_512_hash(const uint8_t *data,
                                          size_t length, uint8_t *digest)
{
  ha_keccak_512_context ctx;
  ha_keccak_512_init(&ctx);
  ha_keccak_512_absorb(&ctx, data, length);
  ha_keccak_512_final(&ctx);
  ha_keccak_512_squeeze(&ctx, digest);
}
