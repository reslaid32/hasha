#include "keccak.h"
#include "md5.h"
#if !defined(HASHAPP_HPP_LOADED)
#define HASHAPP_HPP_LOADED

#if __has_include(<hasha/all.h>)
  #include "./all.h"
  #include "./internal/export.h"
#else
  #error "libhashapp is simply a convenient wrapper for C++. To use it, you must first install the core library, libhasha."
#endif

#include <iomanip>
#include <string>
#include <vector>
#include <sstream>

/*
 * all: calling init, update, final
 * one: calling only oneshot
 */
enum _e_hasha_pp_oneshot_ty {
    E_HASHA_PP_ONESHOT_ALL=0, E_HASHA_PP_ONESHOT_ONE=1, };

#if !defined(HASHA_PP_ONESHOT_TYPE)
#define HASHA_PP_ONESHOT_TYPE 1 /* E_HASHA_PP_ONESHOT_ONE by default */
#endif /* HASHA_PP_ONESHOT_TYPE */

#pragma region decl

namespace hasha
{
    using Digest = std::vector<uint8_t>;

    /* bits->bytes */
    HASHA_PUBLIC_HO_FUNC constexpr size_t bytes(size_t bits) {
        return HASHA_bB(bits);
    }

namespace digest
{
    HASHA_PUBLIC_HO_FUNC void tostream(std::ostream& os, const hasha::Digest& digest) {
        for (size_t i = 0; i < digest.size(); ++i) {
            os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
        }
    }

    HASHA_PUBLIC_HO_FUNC void tostring(std::string& str, const hasha::Digest& digest) {
        std::stringstream ss;
        hasha::digest::tostream(ss, digest);
        str = ss.str();
    }

    HASHA_PUBLIC_HO_FUNC bool compare(const std::string& lhs, const std::string& rhs) {
        if (lhs.size() != rhs.size()) return false;
        return lhs == rhs;
    }

    HASHA_PUBLIC_HO_FUNC bool compare(const hasha::Digest& lhs, const hasha::Digest& rhs) {
        if (lhs.size() != rhs.size()) return false;
        return lhs == rhs;
    }

    HASHA_PUBLIC_HO_FUNC bool compare(const hasha::Digest& lhs, const std::string& rhs) {
        std::string lhs_;
        hasha::digest::tostring(lhs_, lhs);
        return hasha::digest::compare(lhs_, rhs);
    }

    HASHA_PUBLIC_HO_FUNC bool compare(const std::string& lhs, const hasha::Digest& rhs) {
        std::string rhs_;
        hasha::digest::tostring(rhs_, rhs);
        return hasha::digest::compare(lhs, rhs_);
    }
}

namespace crc
{
    constexpr int DIGEST_SIZE = hasha::bytes(32); /* 4 bytes, 32 bits */
    static auto oneshotptr_ = crc32_oneshot;

    /* crc32 */
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, uint32_t& digest);
} /* namespace hasha::crc */

namespace md5
{
    constexpr int DIGEST_SIZE = hasha::bytes(128); /* 16 bytes, 128 bits */
    using ctx_t = md5_context;
    static auto oneshotptr_ = md5_oneshot;
    
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::md5 */

namespace sha1
{
    constexpr int DIGEST_SIZE = hasha::bytes(160); /* 20 bytes, 160 bits */
    using ctx_t = sha1_context;
    static auto oneshotptr_ = sha1_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha1 */

namespace sha2
{

namespace sha224
{
    constexpr int DIGEST_SIZE = hasha::bytes(28); /* 28 bytes, 224 bits */
    using ctx_t = sha2_224_context;
    static auto oneshotptr_ = sha2_224_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha2::sha224 */

namespace sha256
{
    constexpr int DIGEST_SIZE = hasha::bytes(32); /* 32 bytes, 256 bits */
    using ctx_t = sha2_256_context;
    static auto oneshotptr_ = sha2_256_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha2::sha256 */

namespace sha384
{
    constexpr int DIGEST_SIZE = hasha::bytes(48); /* 48 bytes, 384 bits */
    using ctx_t = sha2_384_context;
    static auto oneshotptr_ = sha2_384_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha2::sha384 */

namespace sha512
{
    constexpr int DIGEST_SIZE = hasha::bytes(64); /* 64 bytes, 512 bits */
    using ctx_t = sha2_512_context;
    static auto oneshotptr_ = sha2_512_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha2::sha512 */

namespace sha512_224
{
    constexpr int DIGEST_SIZE = hasha::bytes(28); /* 28 bytes, 224 bits */
    using ctx_t = sha2_512_224_context;
    static auto oneshotptr_ = sha2_512_224_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha2::sha512_224 */

namespace sha512_256
{
    constexpr int DIGEST_SIZE = hasha::bytes(32); /* 32 bytes, 256 bits */
    using ctx_t = sha2_512_256_context;
    static auto oneshotptr_ = sha2_512_224_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha2::sha512_256 */

} /* namespace hasha::sha2 */

namespace sha3
{

namespace sha3_224
{
    constexpr int DIGEST_SIZE = hasha::bytes(28); /* 28 bytes, 224 bits */
    using ctx_t = sha3_224_context;
    static auto oneshotptr_ = sha3_224_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha3::sha3_224 */

namespace sha3_256
{
    constexpr int DIGEST_SIZE = hasha::bytes(32); /* 32 bytes, 256 bits */
    using ctx_t = sha3_256_context;
    static auto oneshotptr_ = sha3_256_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha3::sha3_256 */

namespace sha3_384
{
    constexpr int DIGEST_SIZE = hasha::bytes(48); /* 48 bytes, 384 bits */
    using ctx_t = sha3_384_context;
    static auto oneshotptr_ = sha3_384_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha3::sha3_384 */

namespace sha3_512
{
    constexpr int DIGEST_SIZE = hasha::bytes(64); /* 64 bytes, 512 bits */
    using ctx_t = sha3_512_context;
    static auto oneshotptr_ = sha3_512_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::sha3::sha3_512 */

} /* namespace hasha::sha3 */

namespace keccak
{

namespace keccak224
{
    constexpr int DIGEST_SIZE = hasha::bytes(28); /* 28 bytes, 224 bits */
    using ctx_t = keccak_224_context;
    static auto oneshotptr_ = keccak_224_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::keccak::keccak224 */

namespace keccak256
{
    constexpr int DIGEST_SIZE = hasha::bytes(32); /* 32 bytes, 256 bits */
    using ctx_t = keccak_256_context;
    static auto oneshotptr_ = keccak_256_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::keccak::keccak256 */

namespace keccak384
{
    constexpr int DIGEST_SIZE = hasha::bytes(48); /* 48 bytes, 384 bits */
    using ctx_t = keccak_384_context;
    static auto oneshotptr_ = keccak_384_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::keccak::keccak384 */

namespace keccak512
{
    constexpr int DIGEST_SIZE = hasha::bytes(64); /* 64 bytes, 512 bits */
    using ctx_t = keccak_512_context;
    static auto oneshotptr_ = keccak_512_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest);
} /* namespace hasha::keccak::keccak512 */

} /* namespace hasha::keccak */

namespace blake3
{
    using ctx_t = blake3_context;
    static auto oneshotptr_ = blake3_oneshot;

    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx);
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input);
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest, size_t digestlen);
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest, size_t digestlen);
} /* namespace hasha::blake3 */

} /* namespace hasha */

#pragma endregion /* decl */

/* implementation */
namespace hasha
{

namespace crc
{
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, uint32_t& digest) {
        /* oneshot */
        #if 0
        digest = crc32_oneshot(reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
        #endif
        digest = oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
}

namespace md5
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { md5_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        md5_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(MD5_DIGEST_SIZE);
        md5_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha1
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha1_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha1_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha1_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha2
{

namespace sha224
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha2_224_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_224_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_224_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha256
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha2_256_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_256_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_256_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha384
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha2_384_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_384_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_384_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha512
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha2_512_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_512_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_512_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha512_224
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha2_512_224_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_512_224_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_512_224_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha512_256
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha2_512_256_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha2_512_256_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha2_512_256_finalize(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

} /* sha2 */

namespace sha3
{

namespace sha3_224
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha3_224_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_224_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_224_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha3_256
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha3_256_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_256_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_256_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha3_384
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha3_384_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_384_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_384_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace sha3_512
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { sha3_512_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        sha3_512_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        sha3_512_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

} /* sha3 */

namespace keccak
{

namespace keccak224
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { keccak_224_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_224_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_224_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace keccak256
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { keccak_256_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_256_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_256_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace keccak384
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { keccak_384_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_384_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_384_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

namespace keccak512
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { keccak_512_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        keccak_512_absorb(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest) {
        digest.resize(DIGEST_SIZE);
        keccak_512_squeeze(ctx, digest.data());
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data());
    #endif
    }
}

} /* keccak */

namespace blake3
{
    HASHA_PUBLIC_HO_FUNC void init   (ctx_t *ctx) { blake3_init(ctx); }
    HASHA_PUBLIC_HO_FUNC void update (ctx_t *ctx, const std::string& input) {
        blake3_update(ctx, reinterpret_cast<const uint8_t*>(input.c_str()), input.length());
    }
    HASHA_PUBLIC_HO_FUNC void final  (ctx_t *ctx, hasha::Digest& digest, size_t digestlen) {
        digest.resize(digestlen);
        blake3_final(ctx, digest.data(), digestlen);
    }
    HASHA_PUBLIC_HO_FUNC void oneshot(const std::string& input, hasha::Digest& digest) {
    #if HASHA_PP_ONESHOT_TYPE == 0
        ctx_t ctx;
        init(&ctx);
        update(&ctx, input);
        final(&ctx, digest);
    }
    #elif HASHA_PP_ONESHOT_TYPE == 1
        oneshotptr_(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), digest.data(), digest.size());
    #endif
    }
}

}

#endif /* HASHAPP_HPP_LOADED */