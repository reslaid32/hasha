#define HASHA_LIBRARY_BUILD

#include "../include/hasha/sha3.h"

HASHA_PUBLIC_FUNC void sha3_224_init(sha3_224_context *ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = SHA3_224_RATE;
    ctx->capacity = 200 - SHA3_224_RATE;
    ctx->absorb_index = 0;
    ctx->squeeze_index = SHA3_224_RATE;
}

HASHA_PUBLIC_FUNC void sha3_224_absorb(sha3_224_context *ctx, const uint8_t *data, size_t length) {
    size_t i = 0;
    while (i < length) {
        size_t absorb_bytes = ctx->rate - ctx->absorb_index;
        if (absorb_bytes > length - i) {
            absorb_bytes = length - i;
        }
        for (size_t j = 0; j < absorb_bytes; ++j) {
            ctx->state[ctx->absorb_index + j] ^= data[i + j];
        }
        ctx->absorb_index += absorb_bytes;
        i += absorb_bytes;

        if (ctx->absorb_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->absorb_index = 0;
        }
    }
}

HASHA_PUBLIC_FUNC void sha3_224_finalize(sha3_224_context *ctx) {
    ctx->state[ctx->absorb_index] ^= 0x06; // Padding
    ctx->state[ctx->rate - 1] ^= 0x80;
    keccak_permutation((uint64_t *)ctx->state);
    ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void sha3_224_squeeze(sha3_224_context *ctx, uint8_t *digest) {
    size_t i = 0;
    while (i < SHA3_224_DIGEST_SIZE) {
        if (ctx->squeeze_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->squeeze_index = 0;
        }
        digest[i++] = ctx->state[ctx->squeeze_index++];
    }
}

HASHA_PUBLIC_FUNC void sha3_224(const uint8_t *data, size_t length, uint8_t *digest) {
    sha3_224_context ctx;
    sha3_224_init(&ctx);
    sha3_224_absorb(&ctx, data, length);
    sha3_224_finalize(&ctx);
    sha3_224_squeeze(&ctx, digest);
}

HASHA_PUBLIC_FUNC void sha3_256_init(sha3_256_context *ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = SHA3_256_RATE;
    ctx->capacity = 200 - SHA3_256_RATE;
    ctx->absorb_index = 0;
    ctx->squeeze_index = SHA3_256_RATE;
}

HASHA_PUBLIC_FUNC void sha3_256_absorb(sha3_256_context *ctx, const uint8_t *data, size_t length) {
    size_t i = 0;
    while (i < length) {
        size_t absorb_bytes = ctx->rate - ctx->absorb_index;
        if (absorb_bytes > length - i) {
            absorb_bytes = length - i;
        }
        for (size_t j = 0; j < absorb_bytes; ++j) {
            ctx->state[ctx->absorb_index + j] ^= data[i + j];
        }
        ctx->absorb_index += absorb_bytes;
        i += absorb_bytes;

        if (ctx->absorb_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->absorb_index = 0;
        }
    }
}

HASHA_PUBLIC_FUNC void sha3_256_finalize(sha3_256_context *ctx) {
    ctx->state[ctx->absorb_index] ^= 0x06; // Padding
    ctx->state[ctx->rate - 1] ^= 0x80;
    keccak_permutation((uint64_t *)ctx->state);
    ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void sha3_256_squeeze(sha3_256_context *ctx, uint8_t *digest) {
    size_t i = 0;
    while (i < SHA3_256_DIGEST_SIZE) {
        if (ctx->squeeze_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->squeeze_index = 0;
        }
        digest[i++] = ctx->state[ctx->squeeze_index++];
    }
}

HASHA_PUBLIC_FUNC void sha3_256(const uint8_t *data, size_t length, uint8_t *digest) {
    sha3_256_context ctx;
    sha3_256_init(&ctx);
    sha3_256_absorb(&ctx, data, length);
    sha3_256_finalize(&ctx);
    sha3_256_squeeze(&ctx, digest);
}

HASHA_PUBLIC_FUNC void sha3_384_init(sha3_384_context *ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = SHA3_384_RATE;
    ctx->capacity = 200 - SHA3_384_RATE;
    ctx->absorb_index = 0;
    ctx->squeeze_index = SHA3_384_RATE;
}

HASHA_PUBLIC_FUNC void sha3_384_absorb(sha3_384_context *ctx, const uint8_t *data, size_t length) {
    size_t i = 0;
    while (i < length) {
        size_t absorb_bytes = ctx->rate - ctx->absorb_index;
        if (absorb_bytes > length - i) {
            absorb_bytes = length - i;
        }
        for (size_t j = 0; j < absorb_bytes; ++j) {
            ctx->state[ctx->absorb_index + j] ^= data[i + j];
        }
        ctx->absorb_index += absorb_bytes;
        i += absorb_bytes;

        if (ctx->absorb_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->absorb_index = 0;
        }
    }
}

HASHA_PUBLIC_FUNC void sha3_384_finalize(sha3_384_context *ctx) {
    ctx->state[ctx->absorb_index] ^= 0x06; // Padding
    ctx->state[ctx->rate - 1] ^= 0x80;
    keccak_permutation((uint64_t *)ctx->state);
    ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void sha3_384_squeeze(sha3_384_context *ctx, uint8_t *digest) {
    size_t i = 0;
    while (i < SHA3_384_DIGEST_SIZE) {
        if (ctx->squeeze_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->squeeze_index = 0;
        }
        digest[i++] = ctx->state[ctx->squeeze_index++];
    }
}

HASHA_PUBLIC_FUNC void sha3_384(const uint8_t *data, size_t length, uint8_t *digest) {
    sha3_384_context ctx;
    sha3_384_init(&ctx);
    sha3_384_absorb(&ctx, data, length);
    sha3_384_finalize(&ctx);
    sha3_384_squeeze(&ctx, digest);
}

HASHA_PUBLIC_FUNC void sha3_512_init(sha3_512_context *ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = SHA3_512_RATE;
    ctx->capacity = 200 - SHA3_512_RATE;
    ctx->absorb_index = 0;
    ctx->squeeze_index = SHA3_512_RATE;
}

HASHA_PUBLIC_FUNC void sha3_512_absorb(sha3_512_context *ctx, const uint8_t *data, size_t length) {
    size_t i = 0;
    while (i < length) {
        size_t absorb_bytes = ctx->rate - ctx->absorb_index;
        if (absorb_bytes > length - i) {
            absorb_bytes = length - i;
        }
        for (size_t j = 0; j < absorb_bytes; ++j) {
            ctx->state[ctx->absorb_index + j] ^= data[i + j];
        }
        ctx->absorb_index += absorb_bytes;
        i += absorb_bytes;

        if (ctx->absorb_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->absorb_index = 0;
        }
    }
}

HASHA_PUBLIC_FUNC void sha3_512_finalize(sha3_512_context *ctx) {
    ctx->state[ctx->absorb_index] ^= 0x06; // Padding
    ctx->state[ctx->rate - 1] ^= 0x80;
    keccak_permutation((uint64_t *)ctx->state);
    ctx->squeeze_index = 0;
}

HASHA_PUBLIC_FUNC void sha3_512_squeeze(sha3_512_context *ctx, uint8_t *digest) {
    size_t i = 0;
    while (i < SHA3_512_DIGEST_SIZE) {
        if (ctx->squeeze_index == ctx->rate) {
            keccak_permutation((uint64_t *)ctx->state);
            ctx->squeeze_index = 0;
        }
        digest[i++] = ctx->state[ctx->squeeze_index++];
    }
}

HASHA_PUBLIC_FUNC void sha3_512(const uint8_t *data, size_t length, uint8_t *digest) {
    sha3_512_context ctx;
    sha3_512_init(&ctx);
    sha3_512_absorb(&ctx, data, length);
    sha3_512_finalize(&ctx);
    sha3_512_squeeze(&ctx, digest);
}