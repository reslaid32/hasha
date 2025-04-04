
#ifndef __HASHA_EVP_H
#define __HASHA_EVP_H

#include "./internal/internal.h"
#include "internal/hadefs.h"

#define ha_ctx(hash) ha_##hash##_context

#define ha_init_fun(hash) ha_##hash##_init
#define ha_update_fun(hash) ha_##hash##_update
#define ha_final_fun(hash) ha_##hash##_final
#define ha_hash_fun(hash) ha_##hash##_hash

#define ha_init(hash, ctx) ha_##hash##_init(ctx)
#define ha_update(hash, ctx, buf, buflen) \
  ha_##hash##_update(ctx, buf, buflen)
#define ha_final(hash, ctx, ...) ha_##hash##_final(ctx, ##__VA_ARGS__)
#define ha_hash(hash, buf, buflen, digest, ...) \
  ha_##hash##_hash(ctx, buf, buflen, digest, ##__VA_ARGS__)

#ifdef HA_ADA
#define ha_ada_hash(hash, buf, len, digest, ...) \
  do {                                           \
    ha_ctx(hash) ctx;                            \
    ha_init(hash, &ctx);                         \
    ha_update(hash, &ctx, buf, len);             \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__); \
  } while (0)

#define ha_ada_stream_hash(hash, stream, size, chunksize, buffer, digest, \
                           ...)                                           \
  do {                                                                    \
    ha_ctx(hash) ctx;                                                     \
    ha_init(hash, &ctx);                                                  \
    size_t bytes;                                                         \
    while ((bytes = fread((buffer), (size), (chunksize), (stream))) > 0)  \
    {                                                                     \
      ha_update(hash, &ctx, buffer, bytes);                               \
    }                                                                     \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__);                          \
  } while (0)

#ifdef HA_ADA_COMPATIBILITY
#define ha_buffer_digest(...) ha_ada_hash(__VA_ARGS__)
#define ha_stream_digest(...) ha_ada_stream_hash(__VA_ARGS__)
#endif
#endif

enum ha_evp_hashty ha_enum_base(uint8_t)
{
  HA_EVPTY_BLAKE2B,
  HA_EVPTY_BLAKE2S,
  HA_EVPTY_BLAKE3,
  HA_EVPTY_KECCAK,
  HA_EVPTY_MD5,
  HA_EVPTY_SHA1,
  HA_EVPTY_SHA2,
  HA_EVPTY_SHA3
};

extern const size_t ha_evp_hasher_size;
typedef struct ha_evp_hasher ha_evp_hasher_t;

HA_EXTERN_C_BEG

HA_PUBFUN
struct ha_evp_hasher *ha_evp_hasher_new();

HA_PUBFUN
void ha_evp_hasher_delete(struct ha_evp_hasher *ptr);

HA_PUBFUN
void ha_evp_hasher_init(struct ha_evp_hasher *hasher,
                        enum ha_evp_hashty hashty, size_t digestlen);

HA_PUBFUN
void ha_evp_hasher_cleanup(struct ha_evp_hasher *hasher);

HA_PUBFUN
void ha_evp_hasher_reinit(struct ha_evp_hasher *hasher,
                          enum ha_evp_hashty hashty, size_t digestlen);

HA_PUBFUN
void ha_evp_init(struct ha_evp_hasher *hasher);

HA_PUBFUN
void ha_evp_update(struct ha_evp_hasher *hasher, ha_inbuf_t buf,
                   size_t len);

HA_PUBFUN
void ha_evp_final(struct ha_evp_hasher *hasher, ha_digest_t digest);

HA_PUBFUN
void ha_evp_hash(struct ha_evp_hasher *hasher, ha_inbuf_t buf, size_t len,
                 ha_digest_t digest);

HA_EXTERN_C_END

#ifdef HA_CPLUSPLUS

#include <memory>
#include <stdexcept>
#include <vector>

namespace ha
{

class evp
{
 private:
  void new_hasher()
  {
    hasher_.reset(ha_evp_hasher_new());
    if (!hasher_)
    {
      throw std::runtime_error("Failed to (re)create EVP hasher");
    }
  }

  void init_hasher()
  {
    ha_evp_hasher_init(hasher_.get(), hashty_, digestlen_);
  }

  void reinit_hasher()
  {
    ha_evp_hasher_reinit(hasher_.get(), hashty_, digestlen_);
  }

  void cleanup_hasher() { ha_evp_hasher_cleanup(hasher_.get()); }

  void delete_hasher() { ha_evp_hasher_delete(hasher_.get()); }

 public:
  explicit evp(ha_evp_hashty hashty, size_t digestlen = 0)
      : hashty_(hashty),
        digestlen_(digestlen),
        hasher_(ha_evp_hasher_new(), &ha_evp_hasher_delete)
  {
    if (!hasher_)
    {
      throw std::runtime_error("Failed to create EVP hasher");
    }
    init_hasher();
  }

  evp *set_hashty(ha_evp_hashty hashty)
  {
    hashty_ = hashty;
    return this;
  }

  evp *set_digestlen(size_t digestlen)
  {
    digestlen_ = digestlen;
    return this;
  }

  evp *commit()
  {
    reinit_hasher();
    return this;
  }

  evp *init()
  {
    ha_evp_init(hasher_.get());
    return this;
  }

  evp *update(ha_inbuf_t data, size_t len)
  {
    ha_evp_update(hasher_.get(), data, len);
    return this;
  }

  evp *update(const std::vector<uint8_t> &data)
  {
    update(data.data(), data.size());
    return this;
  }

  evp * final(ha_outbuf_t digest)
  {
    ha_evp_final(hasher_.get(), digest);
    return this;
  }

  evp * final(std::vector<uint8_t> &digest)
  {
    final(digest.data());
    return this;
  }

  evp *hash(ha_inbuf_t data, size_t len, ha_outbuf_t digest)
  {
    ha_evp_hash(hasher_.get(), data, len, digest);
    return this;
  }

  evp *hash(const std::vector<uint8_t> &data, std::vector<uint8_t> &digest)
  {
    digest.resize(digestlen_);
    ha_evp_hash(hasher_.get(), data.data(), data.size(), digest.data());
    return this;
  }

 private:
  ha_evp_hashty hashty_;
  size_t digestlen_;
  std::unique_ptr<ha_evp_hasher_t, decltype(&ha_evp_hasher_delete)>
      hasher_;

  evp(const evp &)            = delete;
  evp &operator=(const evp &) = delete;
};

}  // namespace ha

#endif

#endif