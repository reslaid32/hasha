#define HASHA_LIBRARY_BUILD

#include "../include/hasha/sha3.h"

#include "../include/hasha/keccakf1600.h"

HASHA_PUBLIC_FUNC void ha_sha3_224_init(ha_sha3_224_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = SHA3_224_RATE;
  ctx->capacity      = 200 - SHA3_224_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = SHA3_224_RATE;
}

HASHA_PUBLIC_FUNC void ha_sha3_224_update(ha_sha3_224_context *ctx,
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

HASHA_PUBLIC_FUNC void ha_sha3_224_final(ha_sha3_224_context *ctx,
                                         uint8_t *digest)
{
  ctx->state[ctx->absorb_index] ^= 0x06;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < SHA3_224_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_sha3_224_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest)
{
  ha_sha3_224_context ctx;
  ha_sha3_224_init(&ctx);
  ha_sha3_224_update(&ctx, data, length);
  ha_sha3_224_final(&ctx, digest);
}

HASHA_PUBLIC_FUNC void ha_sha3_256_init(ha_sha3_256_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = SHA3_256_RATE;
  ctx->capacity      = 200 - SHA3_256_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = SHA3_256_RATE;
}

HASHA_PUBLIC_FUNC void ha_sha3_256_update(ha_sha3_256_context *ctx,
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

HASHA_PUBLIC_FUNC void ha_sha3_256_final(ha_sha3_256_context *ctx,
                                         uint8_t *digest)
{
  ctx->state[ctx->absorb_index] ^= 0x06;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < SHA3_256_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_sha3_256_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest)
{
  ha_sha3_256_context ctx;
  ha_sha3_256_init(&ctx);
  ha_sha3_256_update(&ctx, data, length);
  ha_sha3_256_final(&ctx, digest);
}

HASHA_PUBLIC_FUNC void ha_sha3_384_init(ha_sha3_384_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = SHA3_384_RATE;
  ctx->capacity      = 200 - SHA3_384_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = SHA3_384_RATE;
}

HASHA_PUBLIC_FUNC void ha_sha3_384_update(ha_sha3_384_context *ctx,
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

HASHA_PUBLIC_FUNC void ha_sha3_384_final(ha_sha3_384_context *ctx,
                                         uint8_t *digest)
{
  ctx->state[ctx->absorb_index] ^= 0x06;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < SHA3_384_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_sha3_384_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest)
{
  ha_sha3_384_context ctx;
  ha_sha3_384_init(&ctx);
  ha_sha3_384_update(&ctx, data, length);
  ha_sha3_384_final(&ctx, digest);
}

HASHA_PUBLIC_FUNC void ha_sha3_512_init(ha_sha3_512_context *ctx)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = SHA3_512_RATE;
  ctx->capacity      = 200 - SHA3_512_RATE;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = SHA3_512_RATE;
}

HASHA_PUBLIC_FUNC void ha_sha3_512_update(ha_sha3_512_context *ctx,
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

HASHA_PUBLIC_FUNC void ha_sha3_512_final(ha_sha3_512_context *ctx,
                                         uint8_t *digest)
{
  ctx->state[ctx->absorb_index] ^= 0x06;  // Padding
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < SHA3_512_DIGEST_SIZE)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HASHA_PUBLIC_FUNC void ha_sha3_512_hash(const uint8_t *data, size_t length,
                                        uint8_t *digest)
{
  ha_sha3_512_context ctx;
  ha_sha3_512_init(&ctx);
  ha_sha3_512_update(&ctx, data, length);
  ha_sha3_512_final(&ctx, digest);
}