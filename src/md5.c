#define HASHA_LIBRARY_BUILD

#include "../include/hasha/md5.h"

#define MD5_ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))

static const uint32_t MD5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const uint8_t MD5_SHIFT[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

HASHA_PRIVATE_FUNC void md5_transform(ha_md5_context *ctx,
                                      const uint8_t *block)
{
  uint32_t a, b, c, d, f, g, temp;
  uint32_t m[16];

  for (int i = 0; i < 16; ++i)
  {
    m[i] = (block[i * 4]) | (block[i * 4 + 1] << 8) |
           (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];

  for (int i = 0; i < 64; ++i)
  {
    if (i < 16)
    {
      f = MD5_F(b, c, d);
      g = i;
    }
    else if (i < 32)
    {
      f = MD5_G(b, c, d);
      g = (5 * i + 1) % 16;
    }
    else if (i < 48)
    {
      f = MD5_H(b, c, d);
      g = (3 * i + 5) % 16;
    }
    else
    {
      f = MD5_I(b, c, d);
      g = (7 * i) % 16;
    }

    temp = d;
    d    = c;
    c    = b;
    b    = b + MD5_ROTATE_LEFT((a + f + MD5_T[i] + m[g]), MD5_SHIFT[i]);
    a    = temp;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
}

HASHA_PUBLIC_FUNC void ha_md5_init(ha_md5_context *ctx)
{
  ctx->state[0]  = 0x67452301;
  ctx->state[1]  = 0xEFCDAB89;
  ctx->state[2]  = 0x98BADCFE;
  ctx->state[3]  = 0x10325476;
  ctx->bit_count = 0;
  memset(ctx->buffer, 0, MD5_BLOCK_SIZE);
}

HASHA_PUBLIC_FUNC void ha_md5_update(ha_md5_context *ctx,
                                     const uint8_t *data, size_t len)
{
  size_t buffer_space =
      MD5_BLOCK_SIZE - (ctx->bit_count / 8) % MD5_BLOCK_SIZE;
  ctx->bit_count += len * 8;

  if (len >= buffer_space)
  {
    memcpy(ctx->buffer + (MD5_BLOCK_SIZE - buffer_space), data,
           buffer_space);
    md5_transform(ctx, ctx->buffer);
    data += buffer_space;
    len -= buffer_space;

    while (len >= MD5_BLOCK_SIZE)
    {
      md5_transform(ctx, data);
      data += MD5_BLOCK_SIZE;
      len -= MD5_BLOCK_SIZE;
    }
  }

  memcpy(ctx->buffer, data, len);
}

HASHA_PUBLIC_FUNC void ha_md5_final(ha_md5_context *ctx, uint8_t *digest)
{
  size_t buffer_index         = (ctx->bit_count / 8) % MD5_BLOCK_SIZE;
  ctx->buffer[buffer_index++] = 0x80;

  if (buffer_index > MD5_BLOCK_SIZE - 8)
  {
    memset(ctx->buffer + buffer_index, 0, MD5_BLOCK_SIZE - buffer_index);
    md5_transform(ctx, ctx->buffer);
    buffer_index = 0;
  }

  memset(ctx->buffer + buffer_index, 0, MD5_BLOCK_SIZE - buffer_index - 8);
  uint64_t bit_count_le = ctx->bit_count;
  memcpy(ctx->buffer + MD5_BLOCK_SIZE - 8, &bit_count_le, 8);
  md5_transform(ctx, ctx->buffer);

  for (int i = 0; i < 4; i++)
  {
    digest[i * 4]     = (ctx->state[i]) & 0xFF;
    digest[i * 4 + 1] = (ctx->state[i] >> 8) & 0xFF;
    digest[i * 4 + 2] = (ctx->state[i] >> 16) & 0xFF;
    digest[i * 4 + 3] = (ctx->state[i] >> 24) & 0xFF;
  }
}

HASHA_PUBLIC_FUNC void ha_md5_hash(const uint8_t *data, size_t len,
                                   uint8_t *digest)
{
  ha_md5_context ctx;
  ha_md5_init(&ctx);
  ha_md5_update(&ctx, data, len);
  ha_md5_final(&ctx, digest);
}
