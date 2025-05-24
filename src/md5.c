#define HA_BUILD

#include "../include/hasha/md5.h"
#include "../include/hasha/md5_k.h"

#include "./endian.h"

HA_PRVFUN void
md5_transform (ha_md5_context *ctx, const uint8_t *block)
{
  uint32_t a, b, c, d, f, g, temp;
  uint32_t m[16];

#ifdef HA_ONLY_LE
  for (int i = 0; i < 16; i++)
    m[i] = block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16)
           | (block[i * 4 + 3] << 24);
#else
  for (int i = 0; i < 16; i++)
    {
      uint32_t word;
      memcpy (&word, block + i * 4, 4);
      m[i] = le32_to_cpu (word);
    }
#endif

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];

  for (int i = 0; i < 64; ++i)
    {
      if (i < 16)
        {
          f = ha_primitive_md5_f (b, c, d);
          g = i;
        }
      else if (i < 32)
        {
          f = ha_primitive_md5_g (b, c, d);
          g = (5 * i + 1) % 16;
        }
      else if (i < 48)
        {
          f = ha_primitive_md5_h (b, c, d);
          g = (3 * i + 5) % 16;
        }
      else
        {
          f = ha_primitive_md5_i (b, c, d);
          g = (7 * i) % 16;
        }

      temp = d;
      d = c;
      c = b;
      b = b
          + ha_primitive_rotl32 ((a + f + HA_MD5_K[i] + m[g]),
                                 HA_MD5_SHIFT[i]);
      a = temp;
    }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
}

HA_PUBFUN void
ha_md5_init (ha_md5_context *ctx)
{
  // ctx->state[0] = 0x67452301;
  // ctx->state[1] = 0xEFCDAB89;
  // ctx->state[2] = 0x98BADCFE;
  // ctx->state[3] = 0x10325476;
  memcpy (ctx->state, HA_MD5_H0, sizeof (HA_MD5_H0));
  ctx->bit_count = 0;
  memset (ctx->buffer, 0, HA_MD5_BLOCK_SIZE);
}

HA_PUBFUN void
ha_md5_update (ha_md5_context *ctx, ha_inbuf_t data, size_t len)
{
  size_t buffer_space
      = HA_MD5_BLOCK_SIZE - (ctx->bit_count / 8) % HA_MD5_BLOCK_SIZE;
  ctx->bit_count += len * 8;

  if (len >= buffer_space)
    {
      memcpy (ctx->buffer + (HA_MD5_BLOCK_SIZE - buffer_space), data,
              buffer_space);
      md5_transform (ctx, ctx->buffer);
      data += buffer_space;
      len -= buffer_space;

      while (len >= HA_MD5_BLOCK_SIZE)
        {
          md5_transform (ctx, data);
          data += HA_MD5_BLOCK_SIZE;
          len -= HA_MD5_BLOCK_SIZE;
        }
    }

  memcpy (ctx->buffer, data, len);
}

HA_PUBFUN void
ha_md5_final (ha_md5_context *ctx, ha_digest_t digest)
{
  size_t buffer_index = (ctx->bit_count / 8) % HA_MD5_BLOCK_SIZE;
  ctx->buffer[buffer_index++] = 0x80;

  if (buffer_index > HA_MD5_BLOCK_SIZE - 8)
    {
      memset (ctx->buffer + buffer_index, 0, HA_MD5_BLOCK_SIZE - buffer_index);
      md5_transform (ctx, ctx->buffer);
      buffer_index = 0;
    }

  memset (ctx->buffer + buffer_index, 0, HA_MD5_BLOCK_SIZE - buffer_index - 8);

#ifdef HA_ONLY_LE
  uint64_t bit_count_le = ctx->bit_count;
  memcpy (ctx->buffer + HA_MD5_BLOCK_SIZE - 8, &bit_count_le, 8);
#else
  store_le64 (ctx->buffer + HA_MD5_BLOCK_SIZE - 8, ctx->bit_count);
#endif

  md5_transform (ctx, ctx->buffer);

#ifdef HA_ONLY_LE
  for (int i = 0; i < 4; i++)
    {
      digest[i * 4] = (ctx->state[i]) & 0xFF;
      digest[i * 4 + 1] = (ctx->state[i] >> 8) & 0xFF;
      digest[i * 4 + 2] = (ctx->state[i] >> 16) & 0xFF;
      digest[i * 4 + 3] = (ctx->state[i] >> 24) & 0xFF;
    }
#else
  for (int i = 0; i < 4; i++)
    store_le32 (digest + i * 4, ctx->state[i]);
#endif
}

HA_PUBFUN void
ha_md5_hash (ha_inbuf_t data, size_t len, ha_digest_t digest)
{
  ha_md5_context ctx;
  ha_md5_init (&ctx);
  ha_md5_update (&ctx, data, len);
  ha_md5_final (&ctx, digest);
}
