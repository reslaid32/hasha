
#ifndef __hasha_imp_keccak_h
#define __hasha_imp_keccak_h

#include "../include/hasha/keccak.h"
#include "../include/hasha/keccakf1600.h"

HA_PRVFUN void ha_imp_keccak_init(ha_keccak_context *ctx, size_t rate)
{
  memset(ctx->state, 0, sizeof(ctx->state));
  ctx->rate          = rate;
  ctx->capacity      = 200 - rate;
  ctx->absorb_index  = 0;
  ctx->squeeze_index = rate;
}

HA_PRVFUN
void ha_imp_keccak_update(ha_keccak_context *ctx, ha_inbuf_t buf,
                          size_t len)
{
  size_t i = 0;
  while (i < len)
  {
    size_t absorb_bytes = ctx->rate - ctx->absorb_index;
    if (absorb_bytes > len - i) { absorb_bytes = len - i; }
    for (size_t j = 0; j < absorb_bytes; ++j)
    {
      ctx->state[ctx->absorb_index + j] ^= buf[i + j];
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

HA_PRVFUN
void ha_imp_keccak_final(ha_keccak_context *ctx, uint8_t padbyte,
                         ha_digest_t digest, size_t digestlen)
{
  ctx->state[ctx->absorb_index] ^= padbyte;
  ctx->state[ctx->rate - 1] ^= 0x80;
  ha_keccakf1600((uint64_t *)ctx->state);
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < digestlen)
  {
    if (ctx->squeeze_index == ctx->rate)
    {
      ha_keccakf1600((uint64_t *)ctx->state);
      ctx->squeeze_index = 0;
    }
    digest[i++] = ctx->state[ctx->squeeze_index++];
  }
}

HA_PRVFUN
void ha_imp_keccak_hash(uint8_t padbyte, ha_inbuf_t buf, size_t len,
                        size_t rate, ha_digest_t digest, size_t digestlen)
{
  ha_keccak_context ctx;
  ha_imp_keccak_init(&ctx, rate);
  ha_imp_keccak_update(&ctx, buf, len);
  ha_imp_keccak_final(&ctx, padbyte, digest, digestlen);
}

#endif