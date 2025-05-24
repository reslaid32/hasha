#define HA_BUILD

#include "../include/hasha/sha1.h"
#include "../include/hasha/sha1_k.h"

#include "./endian.h"

HA_PUBFUN void
ha_sha1_transform (ha_sha1_context *ctx, const uint8_t *block)
{
  uint32_t w[80];
  uint32_t a, b, c, d, e;

#ifdef HA_ONLY_LE
  for (int i = 0; i < 16; i++)
    w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16)
           | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
#else
  for (int i = 0; i < 16; i++)
    {
      uint32_t word;
      memcpy (&word, block + i * 4, 4);
      w[i] = be32_to_cpu (word);
    }
#endif

  for (int i = 0; i < 16; i++)
    {
      w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16)
             | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

  for (int i = 16; i < 80; i++)
    {
      w[i] = ha_primitive_rotl32 (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16],
                                  1);
    }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  for (int i = 0; i < 80; i++)
    {
      uint32_t f, k;

      if (i < 20)
        {
          f = (b & c) | ((~b) & d);
          k = HA_SHA1_K[0];
        }
      else if (i < 40)
        {
          f = b ^ c ^ d;
          k = HA_SHA1_K[1];
        }
      else if (i < 60)
        {
          f = (b & c) | (b & d) | (c & d);
          k = HA_SHA1_K[2];
        }
      else
        {
          f = b ^ c ^ d;
          k = HA_SHA1_K[3];
        }

      uint32_t temp = ha_primitive_rotl32 (a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = ha_primitive_rotl32 (b, 30);
      b = a;
      a = temp;
    }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
}

HA_PUBFUN void
ha_sha1_init (ha_sha1_context *ctx)
{
  // ctx->state[0] = 0x67452301;
  // ctx->state[1] = 0xEFCDAB89;
  // ctx->state[2] = 0x98BADCFE;
  // ctx->state[3] = 0x10325476;
  // ctx->state[4] = 0xC3D2E1F0;
  memcpy (ctx->state, HA_SHA1_H0, sizeof (HA_SHA1_H0));
  ctx->bit_count = 0;
  memset (ctx->buffer, 0, HA_SHA1_BLOCK_SIZE);
}

HA_PUBFUN void
ha_sha1_update (ha_sha1_context *ctx, ha_inbuf_t data, size_t len)
{
  size_t buffer_space
      = HA_SHA1_BLOCK_SIZE - (ctx->bit_count / 8) % HA_SHA1_BLOCK_SIZE;
  ctx->bit_count += len * 8;

  if (len >= buffer_space)
    {
      memcpy (ctx->buffer + (HA_SHA1_BLOCK_SIZE - buffer_space), data,
              buffer_space);
      ha_sha1_transform (ctx, ctx->buffer);
      data += buffer_space;
      len -= buffer_space;

      while (len >= HA_SHA1_BLOCK_SIZE)
        {
          ha_sha1_transform (ctx, data);
          data += HA_SHA1_BLOCK_SIZE;
          len -= HA_SHA1_BLOCK_SIZE;
        }
    }

  memcpy (ctx->buffer, data, len);
}

HA_PUBFUN void
ha_sha1_final (ha_sha1_context *ctx, ha_digest_t digest)
{
  size_t buffer_index = (ctx->bit_count / 8) % HA_SHA1_BLOCK_SIZE;
  ctx->buffer[buffer_index++] = 0x80;

  if (buffer_index > HA_SHA1_BLOCK_SIZE - 8)
    {
      memset (ctx->buffer + buffer_index, 0,
              HA_SHA1_BLOCK_SIZE - buffer_index);
      ha_sha1_transform (ctx, ctx->buffer);
      buffer_index = 0;
    }

  memset (ctx->buffer + buffer_index, 0,
          HA_SHA1_BLOCK_SIZE - buffer_index - 8);

#ifdef HA_ONLY_LE
  uint64_t bit_count_be = (ctx->bit_count << 56)
                          | ((ctx->bit_count & 0x0000FF0000000000ULL) >> 8)
                          | ((ctx->bit_count & 0x00FF000000000000ULL) >> 16)
                          | ((ctx->bit_count & 0xFF00000000000000ULL) >> 24);
  memcpy (ctx->buffer + HA_SHA1_BLOCK_SIZE - 8, &bit_count_be, 8);
#else
  store_be64 (ctx->buffer + HA_SHA1_BLOCK_SIZE - 8, ctx->bit_count);
#endif

  ha_sha1_transform (ctx, ctx->buffer);

#ifdef HA_ONLY_LE
  for (int i = 0; i < 5; i++)
    {
      digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
      digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
      digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
      digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
#else
  for (int i = 0; i < 5; i++)
    store_be32 (digest + i * 4, ctx->state[i]);
#endif
}

HA_PUBFUN void
ha_sha1_hash (ha_inbuf_t data, size_t len, ha_digest_t digest)
{
  ha_sha1_context ctx;
  ha_sha1_init (&ctx);
  ha_sha1_update (&ctx, data, len);
  ha_sha1_final (&ctx, digest);
}
