
#ifndef __hasha_imp_keccak_h
#define __hasha_imp_keccak_h

#include "../include/hasha/keccak.h"
#include "../include/hasha/keccakf1600.h"
#include "./endian.h"

HA_PRVFUN void
ha_imp_keccak_init (ha_keccak_context *ctx, size_t rate)
{
  memset (ctx->state, 0, sizeof (ctx->state));
  ctx->rate = rate;
  ctx->capacity = 200 - rate;
  ctx->absorb_index = 0;
  ctx->squeeze_index = rate;
}

HA_PRVFUN
void
ha_imp_keccak_update (ha_keccak_context *ctx, ha_inbuf_t buf, size_t len)
{
  size_t i = 0;
  while (i < len)
    {
      size_t absorb_bytes = ctx->rate - ctx->absorb_index;
      if (absorb_bytes > len - i)
        absorb_bytes = len - i;
      for (size_t j = 0; j < absorb_bytes; ++j)
        ctx->state[ctx->absorb_index + j] ^= buf[i + j];
      ctx->absorb_index += absorb_bytes;
      i += absorb_bytes;

      if (ctx->absorb_index == ctx->rate)
        {
#ifdef HA_ONLY_LE
          ha_keccakf1600 ((uint64_t *)ctx->state);
#else
          uint64_t state_words[25];
          for (size_t k = 0; k < 25; k++)
            {
              uint64_t word;
              memcpy (&word, ctx->state + k * 8, 8);
              state_words[k] = le64_to_cpu (word);
            }
          ha_keccakf1600 (state_words);
          for (size_t k = 0; k < 25; k++)
            store_le64 (ctx->state + k * 8, state_words[k]);
#endif
          ctx->absorb_index = 0;
        }
    }
}

HA_PRVFUN
void
ha_imp_keccak_final (ha_keccak_context *ctx, uint8_t padbyte,
                     ha_digest_t digest, size_t digestlen)
{
#ifndef HA_ONLY_LE
  uint64_t state_words[25];
  for (size_t k = 0; k < 25; k++)
    {
      uint64_t word;
      memcpy (&word, ctx->state + k * 8, 8);
      state_words[k] = le64_to_cpu (word);
    }
#endif

#ifdef HA_ONLY_LE
  ctx->state[ctx->absorb_index] ^= padbyte;
  ctx->state[ctx->rate - 1] ^= 0x80;
#else
  size_t pad_word_idx = ctx->absorb_index / 8;
  size_t pad_byte_idx = ctx->absorb_index % 8;
  state_words[pad_word_idx] ^= ((uint64_t)padbyte << (8 * pad_byte_idx));
  size_t rate_word_idx = (ctx->rate - 1) / 8;
  size_t rate_byte_idx = (ctx->rate - 1) % 8;
  state_words[rate_word_idx] ^= ((uint64_t)0x80 << (8 * rate_byte_idx));
#endif

#ifdef HA_ONLY_LE
  ha_keccakf1600 ((uint64_t *)ctx->state);
#else
  ha_keccakf1600 (state_words);
#endif
  ctx->squeeze_index = 0;

  size_t i = 0;
  while (i < digestlen)
    {
      if (ctx->squeeze_index == ctx->rate)
        {
#ifdef HA_ONLY_LE
          ha_keccakf1600 ((uint64_t *)ctx->state);
#else
          ha_keccakf1600 (state_words);
#endif
          ctx->squeeze_index = 0;
        }
#ifdef HA_ONLY_LE
      digest[i++] = ctx->state[ctx->squeeze_index++];
#else
      size_t word_idx = ctx->squeeze_index / 8;
      size_t byte_idx = ctx->squeeze_index % 8;
      digest[i++] = (state_words[word_idx] >> (8 * byte_idx)) & 0xFF;
      ctx->squeeze_index++;
#endif
    }

#ifndef HA_ONLY_LE
  for (size_t k = 0; k < 25; k++)
    store_le64 (ctx->state + k * 8, state_words[k]);
#endif
}

HA_PRVFUN
void
ha_imp_keccak_hash (uint8_t padbyte, ha_inbuf_t buf, size_t len, size_t rate,
                    ha_digest_t digest, size_t digestlen)
{
  ha_keccak_context ctx;
  ha_imp_keccak_init (&ctx, rate);
  ha_imp_keccak_update (&ctx, buf, len);
  ha_imp_keccak_final (&ctx, padbyte, digest, digestlen);
}

#endif