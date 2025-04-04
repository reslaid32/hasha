#define HA_BUILD

#include "../include/hasha/keccak.h"

#include "../include/hasha/keccakf1600.h"

HA_PUBFUN void ha_keccak_224_init(ha_keccak_224_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = HA_KECCAK_224_RATE;
  ctx->capacity      = 200 - HA_KECCAK_224_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = HA_KECCAK_224_RATE;
}

HA_PUBFUN void ha_keccak_224_update(ha_keccak_224_context *ctx,
                                    ha_inbuf_t data, size_t length)
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

HA_PUBFUN void ha_keccak_224_final(ha_keccak_224_context *ctx,
                                   ha_digest_t digest)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < HA_KECCAK_224_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}
HA_PUBFUN void ha_keccak_224_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_224_context ctx;
  ha_keccak_224_init(&ctx);
  ha_keccak_224_update(&ctx, data, length);
  ha_keccak_224_final(&ctx, digest);
}

HA_PUBFUN void ha_keccak_256_init(ha_keccak_256_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = HA_KECCAK_256_RATE;
  ctx->capacity      = 200 - HA_KECCAK_256_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = HA_KECCAK_256_RATE;
}

HA_PUBFUN void ha_keccak_256_update(ha_keccak_256_context *ctx,
                                    ha_inbuf_t data, size_t length)
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

HA_PUBFUN void ha_keccak_256_final(ha_keccak_256_context *ctx,
                                   ha_digest_t digest)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < HA_KECCAK_256_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HA_PUBFUN void ha_keccak_256_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_256_context ctx;
  ha_keccak_256_init(&ctx);
  ha_keccak_256_update(&ctx, data, length);
  ha_keccak_256_final(&ctx, digest);
}

HA_PUBFUN void ha_keccak_384_init(ha_keccak_384_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = HA_KECCAK_384_RATE;
  ctx->capacity      = 200 - HA_KECCAK_384_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = HA_KECCAK_384_RATE;
}

HA_PUBFUN void ha_keccak_384_update(ha_keccak_384_context *ctx,
                                    ha_inbuf_t data, size_t length)
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

HA_PUBFUN void ha_keccak_384_final(ha_keccak_384_context *ctx,
                                   ha_digest_t digest)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < HA_KECCAK_384_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HA_PUBFUN void ha_keccak_384_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_384_context ctx;
  ha_keccak_384_init(&ctx);
  ha_keccak_384_update(&ctx, data, length);
  ha_keccak_384_final(&ctx, digest);
}

HA_PUBFUN void ha_keccak_512_init(ha_keccak_512_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = HA_KECCAK_512_RATE;
  ctx->capacity      = 200 - HA_KECCAK_512_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = HA_KECCAK_512_RATE;
}

HA_PUBFUN void ha_keccak_512_update(ha_keccak_512_context *ctx,
                                    ha_inbuf_t data, size_t length)
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

HA_PUBFUN void ha_keccak_512_final(ha_keccak_512_context *ctx,
                                   ha_digest_t digest)
{
  ctx->state[ctx->absorb_index] ^= 0x01;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < HA_KECCAK_512_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HA_PUBFUN void ha_keccak_512_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_512_context ctx;
  ha_keccak_512_init(&ctx);
  ha_keccak_512_update(&ctx, data, length);
  ha_keccak_512_final(&ctx, digest);
}
