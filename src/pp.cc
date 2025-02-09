#include "../include/hasha/pp/pp.hpp"

namespace hasha
{

namespace crc
{
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, uint32_t& digest) {
        digest = crc32(reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
}

namespace md5
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { md5_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        md5_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(MD5_DIGEST_SIZE);
        md5_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
}

namespace sha1
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha1_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha1_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha1_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
}

namespace sha2
{

namespace sha224
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha2_224_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_224_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_224_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha256
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha2_256_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_256_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_256_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha384
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha2_384_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_384_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_384_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha512
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha2_512_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_512_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_512_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha512_224
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha2_512_224_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_512_224_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_512_224_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha512_256
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha2_512_256_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_512_256_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_512_256_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

} /* sha2 */

namespace sha3
{

namespace sha3_224
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha3_224_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_224_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_224_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha3_256
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha3_256_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_256_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_256_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha3_384
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha3_384_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_384_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_384_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace sha3_512
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { sha3_512_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_512_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_512_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

} /* sha3 */

namespace keccak
{

namespace keccak224
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { keccak_224_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_224_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_224_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace keccak256
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { keccak_256_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_256_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_256_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace keccak384
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { keccak_384_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_384_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_384_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

namespace keccak512
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { keccak_512_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_512_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_512_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    } 
}

} /* keccak */

namespace blake3
{
    HASHA_PUBLIC_FUNC void init   (ctx_t *ctx) { blake3_init(ctx); }
    HASHA_PUBLIC_FUNC void update (ctx_t *ctx, const std::string& input) {
        blake3_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_FUNC void final  (ctx_t *ctx, hasha::Digest& digest, size_t digestlen) {
        digest.resize(digestlen);
        blake3_final(ctx, digest.data(), digestlen);
    }
    HASHA_PUBLIC_FUNC void oneshot(const std::string& input, hasha::Digest& digest, size_t digestlen) {
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest, digestlen);
    }
}

}