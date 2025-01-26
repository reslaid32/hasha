#define HASHA_LIBRARY_BUILD

#include "../include/hasha/sha1.h"

#define SHA1_ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

HASHA_PUBLIC_FUNC void sha1_transform(sha1_context *ctx, const uint8_t *block) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;

    for (int i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = SHA1_K[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = SHA1_K[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1_K[2];
        } else {
            f = b ^ c ^ d;
            k = SHA1_K[3];
        }

        uint32_t temp = SHA1_ROTL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

HASHA_PUBLIC_FUNC void sha1_init(sha1_context *ctx) {
    // ctx->state[0] = 0x67452301;
    // ctx->state[1] = 0xEFCDAB89;
    // ctx->state[2] = 0x98BADCFE;
    // ctx->state[3] = 0x10325476;
    // ctx->state[4] = 0xC3D2E1F0;
    memcpy(ctx->state, SHA1_H0, sizeof(SHA1_H0));
    ctx->bit_count = 0;
    memset(ctx->buffer, 0, SHA1_BLOCK_SIZE);
}

HASHA_PUBLIC_FUNC void sha1_update(sha1_context *ctx, const uint8_t *data, size_t len) {
    size_t buffer_space = SHA1_BLOCK_SIZE - (ctx->bit_count / 8) % SHA1_BLOCK_SIZE;
    ctx->bit_count += len * 8;

    if (len >= buffer_space) {
        memcpy(ctx->buffer + (SHA1_BLOCK_SIZE - buffer_space), data, buffer_space);
        sha1_transform(ctx, ctx->buffer);
        data += buffer_space;
        len -= buffer_space;

        while (len >= SHA1_BLOCK_SIZE) {
            sha1_transform(ctx, data);
            data += SHA1_BLOCK_SIZE;
            len -= SHA1_BLOCK_SIZE;
        }
    }

    memcpy(ctx->buffer, data, len);
}

HASHA_PUBLIC_FUNC void sha1_finalize(sha1_context *ctx, uint8_t *digest) {
    size_t buffer_index = (ctx->bit_count / 8) % SHA1_BLOCK_SIZE;
    ctx->buffer[buffer_index++] = 0x80;

    if (buffer_index > SHA1_BLOCK_SIZE - 8) {
        memset(ctx->buffer + buffer_index, 0, SHA1_BLOCK_SIZE - buffer_index);
        sha1_transform(ctx, ctx->buffer);
        buffer_index = 0;
    }

    memset(ctx->buffer + buffer_index, 0, SHA1_BLOCK_SIZE - buffer_index - 8);
    uint64_t bit_count_be = (ctx->bit_count << 56) | ((ctx->bit_count & 0x0000FF0000000000ULL) >> 8) |
                            ((ctx->bit_count & 0x00FF000000000000ULL) >> 16) | ((ctx->bit_count & 0xFF00000000000000ULL) >> 24);
    memcpy(ctx->buffer + SHA1_BLOCK_SIZE - 8, &bit_count_be, 8);
    sha1_transform(ctx, ctx->buffer);

    for (int i = 0; i < 5; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

HASHA_PUBLIC_FUNC void sha1(const uint8_t *data, size_t len, uint8_t *digest) {
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_finalize(&ctx, digest);
}
