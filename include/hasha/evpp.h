#pragma once

#include <memory>
#include <stdexcept>
#include <vector>

#include "evp.h"
#include "internal/hadefs.h"
#include "io.h"

#if defined(HA_EVPP_AUTO_COMMIT)
#define ha_evpp_auto_commit() commit()
#else
#define ha_evpp_auto_commit()
#endif

namespace hasha
{
using string      = std::string;
using byte        = uint8_t;

using raw_digest  = byte *;
using raw_cdigest = const byte *;

using digest      = std::vector<byte>;

struct basic_encoding
{
 public:
  virtual std::string encode(digest &digest)                       = 0;
  virtual std::string encode(raw_cdigest digest, size_t size)      = 0;
  virtual digest      decode(const std::string &str)               = 0;
  virtual void        decode(const std::string &str, raw_digest digest,
                             size_t size)                          = 0;
  virtual void        decode(digest &digest, const std::string &s) = 0;
};

namespace encodings
{
struct hex_encoding : public basic_encoding
{
 public:
  HA_INL_FUN
  std::string encode(digest &digest) override
  {
    std::string str(ha_hash2str_bound(digest.size()), '\0');
    ha_hash2str(str.data(), digest.data(), digest.size());
    return str;
  }

  HA_INL_FUN
  std::string encode(raw_cdigest digest, size_t size) override
  {
    std::string str(ha_hash2str_bound(size), '\0');
    ha_hash2str(str.data(), digest, size);
    return str;
  }

  HA_INL_FUN
  digest decode(const std::string &s) override
  {
    digest digest(ha_str2hash_bound(s.length()));
    ha_str2hash(digest.data(), s.data(), digest.size());
    return digest;
  }

  HA_INL_FUN
  void decode(const std::string &s, raw_digest digest,
              size_t size) override
  {
    ha_str2hash(digest, s.data(), size);
  }

  HA_INL_FUN
  void decode(digest &digest, const std::string &s) override
  {
    digest.resize(ha_str2hash_bound(s.length()));
    ha_str2hash(digest.data(), s.data(), digest.size());
  }
};

using hex = hex_encoding;
}  // namespace encodings

template <typename Encoding = encodings::hex_encoding>
HA_HDR_PUBFUN void put(
    std::ostream &os, raw_cdigest digest, size_t size,
    const char               *end      = NULL,
    std::shared_ptr<Encoding> encoding = std::make_shared<Encoding>())
{
  string s = encoding->encode(digest, size);
  os << s;
  if (end) os << string(end);
}

template <typename Encoding = encodings::hex_encoding>
HA_HDR_PUBFUN void put(std::ostream &os, digest &digest,
                       const char                      *end = NULL,
                       const std::shared_ptr<Encoding> &encoding =
                           std::make_shared<Encoding>())
{
  put<Encoding>(os, digest.data(), digest.size(), end, encoding);
}

template <typename Encoding = encodings::hex_encoding>
HA_HDR_PUBFUN void put(FILE *stream, raw_digest digest, size_t size,
                       const char                      *end = NULL,
                       const std::shared_ptr<Encoding> &encoding =
                           std::make_shared<Encoding>())
{
  if (!stream) return;
  string s = encoding->encode(digest, size);
  fprintf(stream, "%s", s.c_str());
  if (end) fprintf(stream, "%s", end);
  return;
}

template <typename Encoding = encodings::hex_encoding>
HA_HDR_PUBFUN void put(FILE *stream, digest &digest,
                       const char                      *end = NULL,
                       const std::shared_ptr<Encoding> &encoding =
                           std::make_shared<Encoding>())
{
  put<Encoding>(stream, digest.data(), digest.size(), end, encoding);
}

HA_HDR_PUBFUN
void put(FILE *file, raw_cdigest digest, size_t size,
         const char *end = NULL)
{
  ha_fputhash(file, digest, size, end);
}

HA_HDR_PUBFUN
void put(digest &digest, const char *end = NULL)
{
  put(stdout, digest, end);
}

HA_HDR_PUBFUN
void put(raw_cdigest digest, size_t size, const char *end = NULL)
{
  put(stdout, digest, size, end);
}

HA_HDR_PUBFUN
bool compare(const digest &lhs, const digest &rhs)
{
  if (lhs.size() != rhs.size()) return false;
  size_t len = std::min /* using min, not max — safe for UB */ (
      lhs.size(), rhs.size());
  return ha_cmphash(lhs.data(), rhs.data(), len) == 0;
}

HA_HDR_PUBFUN
bool compare(const raw_cdigest lhs, size_t lsize, const raw_cdigest rhs,
             size_t rsize)
{
  if (lsize != rsize) return false;
  size_t len =
      std::min /* using min, not max — safe for UB */ (lsize, rsize);
  return ha_cmphash(lhs, rhs, len) == 0;
}

HA_HDR_PUBFUN
bool compare(const digest &lhs, const std::string &rhs)
{
  size_t len = std::min /* using min, not max — safe for UB */ (
      lhs.size(), rhs.size());
  return ha_cmphashstr(lhs.data(), rhs.data(), len) == 0;
}

/**
 * @class Hasher
 * @brief C++ wrapper for the EVP hasher.
 *
 * This class provides a C++ interface for using the EVP hasher,
 * making it easier to work with hashing algorithms in object-oriented
 * code.
 */
class Hasher
{
 public:
  explicit Hasher(ha_evp_hashty type      = HA_EVPTY_UNDEFINED,
                  size_t        digestlen = 0)
      : hasher_(ha_evp_hasher_new(), &ha_evp_hasher_delete)
  {
    if (!hasher_) throw std::runtime_error("Failed to create EVP hasher");
    setup(type, digestlen);
    commit();
  }

  ~Hasher()                             = default;
  Hasher(const Hasher &)                = delete;
  Hasher &operator=(const Hasher &)     = delete;
  Hasher(Hasher &&) noexcept            = default;
  Hasher &operator=(Hasher &&) noexcept = default;

  auto    setType(ha_evp_hashty type) -> Hasher &
  {
    signed long tmp = 0;

    hashty_         = type;
    if ((tmp = ha_evp_hashty_get_digestlen(type)) > 0)
      setDigestLength(tmp);

    return *this;
  }

  auto setDigestLength(size_t length) -> Hasher &
  {
    digestlen_ = length;
    ha_evpp_auto_commit();
    return *this;
  }

  auto setup(ha_evp_hashty hashty, size_t length = 0) -> Hasher &
  {
    setType(hashty);
    if (length) setDigestLength(length);
    return *this;
  }

  auto getType() const { return hashty_; }

  auto getType(ha_evp_hashty &hashty) -> Hasher &
  {
    hashty = hashty_;
    return *this;
  }

  auto getDigestLength() const { return digestlen_; }

  auto getDigestLength(size_t &digestlen) -> Hasher &
  {
    digestlen = digestlen_;
    return *this;
  }

  auto init() -> Hasher &
  {
    ha_evp_init(hasher_.get());
    return *this;
  }

  auto update(const void *data, size_t length) -> Hasher &
  {
    ha_evp_update(hasher_.get(), static_cast<const uint8_t *>(data),
                  length);
    return *this;
  }

  auto update(const std::vector<uint8_t> &data) -> Hasher &
  {
    return update(data.data(), data.size());
  }

  auto update(const char *str) -> Hasher &
  {
    return update(str, strlen(str));
  }

  auto update(const std::string &str) -> Hasher &
  {
    return update(str.data(), str.size());
  }

  auto final(uint8_t *digest) -> Hasher &
  {
    ha_evp_final(hasher_.get(), digest);
    return *this;
  }

  auto final(std::vector<uint8_t> &digest) -> Hasher &
  {
    digest.resize(digestlen_);
    final(digest.data());
    return *this;
  }

  auto final()
  {
    std::vector<uint8_t> digest(digestlen_);
    final(digest);
    return digest;
  }

  auto hash(const uint8_t *data, size_t length, uint8_t *digest)
      -> Hasher &
  {
    ha_evp_hash(hasher_.get(), data, length, digest);
    return *this;
  }

  auto hash(const std::vector<uint8_t> &data, std::vector<uint8_t> &digest)
      -> Hasher &
  {
    digest.resize(digestlen_);
    hash(data.data(), data.size(), digest.data());
    return *this;
  }

  auto hash(const std::string &str, std::vector<uint8_t> &digest)
      -> Hasher &
  {
    std::vector<uint8_t> data(str.begin(), str.end());
    return hash(data, digest);
  }

  auto commit() -> Hasher &
  {
    if (hasher_) ha_evp_hasher_reinit(hasher_.get(), hashty_, digestlen_);
    return *this;
  }

  auto ptr() { return this; }

  auto ref() -> Hasher & { return *this; }

 private:
  ha_evp_hashty hashty_;
  size_t        digestlen_;
  std::unique_ptr<ha_evp_hasher_t, decltype(&ha_evp_hasher_delete)>
      hasher_;
};

#ifdef HA_EVPP_COMPATIBILITY
/**
 * @class evp
 * @brief C++ wrapper for the EVP hasher.
 *
 * This class provides a C++ interface for using the EVP hasher,
 * making it easier to work with hashing algorithms in object-oriented
 * code.
 */
class evp
{
 private:
  /**
   * @brief Allocates a new EVP hasher.
   */
  void new_hasher()
  {
    hasher_.reset(ha_evp_hasher_new());
    if (!hasher_)
      throw std::runtime_error("Failed to (re)create EVP hasher");
  }

  /**
   * @brief Initializes the EVP hasher.
   */
  void init_hasher()
  {
    ha_evp_hasher_init(hasher_.get(), hashty_, digestlen_);
  }

  /**
   * @brief Reinitializes the EVP hasher.
   */
  void reinit_hasher()
  {
    ha_evp_hasher_reinit(hasher_.get(), hashty_, digestlen_);
  }

  /**
   * @brief Cleans up the EVP hasher.
   */
  void cleanup_hasher() { ha_evp_hasher_cleanup(hasher_.get()); }

  /**
   * @brief Deletes the EVP hasher.
   */
  void delete_hasher() { ha_evp_hasher_delete(hasher_.get()); }

 public:
  /**
   * @brief Constructs a new evp object with the specified hash algorithm.
   */
  explicit evp(ha_evp_hashty hashty, size_t digestlen = 0)
      : hashty_(hashty),
        digestlen_(digestlen),
        hasher_(ha_evp_hasher_new(), &ha_evp_hasher_delete)
  {
    if (!hasher_) throw std::runtime_error("Failed to create EVP hasher");
    init_hasher();
  }

  /**
   * @brief Sets the hash algorithm type.
   */
  evp *set_hashty(ha_evp_hashty hashty)
  {
    hashty_ = hashty;
    return this;
  }

  /**
   * @brief Sets the digest length.
   */
  evp *set_digestlen(size_t digestlen)
  {
    digestlen_ = digestlen;
    return this;
  }

  /**
   * @brief Commits the changes (reinitializes the hasher).
   */
  evp *commit()
  {
    reinit_hasher();
    return this;
  }

  /**
   * @brief Initializes the EVP hasher.
   */
  evp *init()
  {
    ha_evp_init(hasher_.get());
    return this;
  }

  /**
   * @brief Updates the EVP hasher with data.
   */
  evp *update(ha_inbuf_t data, size_t len)
  {
    ha_evp_update(hasher_.get(), data, len);
    return this;
  }

  /**
   * @brief Updates the EVP hasher with a vector of data.
   */
  evp *update(const std::vector<uint8_t> &data)
  {
    update(data.data(), data.size());
    return this;
  }

  /**
   * @brief Finalizes the hash computation and returns the digest.
   */
  evp * final(ha_outbuf_t digest)
  {
    ha_evp_final(hasher_.get(), digest);
    return this;
  }

  /**
   * @brief Finalizes the hash computation and stores the digest in a
   * vector.
   */
  evp * final(std::vector<uint8_t> &digest)
  {
    digest.resize(digestlen_);
    final(digest.data());
    return this;
  }

  /**
   * @brief Computes the hash and stores the result in the digest.
   */
  evp *hash(ha_inbuf_t data, size_t len, ha_outbuf_t digest)
  {
    ha_evp_hash(hasher_.get(), data, len, digest);
    return this;
  }

  /**
   * @brief Computes the hash for a vector of data.
   */
  evp *hash(const std::vector<uint8_t> &data, std::vector<uint8_t> &digest)
  {
    digest.resize(digestlen_);
    ha_evp_hash(hasher_.get(), data.data(), data.size(), digest.data());
    return this;
  }

 private:
  ha_evp_hashty hashty_;    /**< Hash algorithm type */
  size_t        digestlen_; /**< Digest length */
  std::unique_ptr<ha_evp_hasher_t, decltype(&ha_evp_hasher_delete)>
      hasher_;              /**< EVP hasher instance */

  evp(const evp &)            = delete;
  evp &operator=(const evp &) = delete;
};
#endif

}  // namespace hasha

#ifdef HA_EVPP_COMPATIBILITY
namespace ha = hasha;
#endif
