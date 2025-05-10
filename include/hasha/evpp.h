#pragma once

#include <memory>
#include <stdexcept>
#include <vector>

#include "evp.h"
#include "internal/hadefs.h"
#include "io.h"

#if defined(__cpp_lib_span) && __cpp_lib_span >= 202002L
#include <span>
#endif

#if defined(HA_EVPP_AUTO_COMMIT)
#define ha_evpp_auto_commit() commit()
#else
#define ha_evpp_auto_commit()
#endif

namespace hasha
{

using string = std::string;
using digest = std::vector<uint8_t>;

namespace hex
{

HA_HDR_PUBFUN
std::string encode(digest &digest)
{
  std::string str(ha_hash2str_bound(digest.size()), '\0');
  ha_hash2str(str.data(), digest.data(), digest.size());
  return str;
}

HA_HDR_PUBFUN
void encode(std::string &s, digest &digest)
{
  s.resize(ha_hash2str_bound(digest.size()));
  ha_hash2str(s.data(), digest.data(), digest.size());
}

HA_HDR_PUBFUN
digest decode(const std::string &s)
{
  digest digest(ha_str2hash_bound(s.length()));
  ha_str2hash(digest.data(), s.data(), digest.size());
  return digest;
}

HA_HDR_PUBFUN
void decode(digest &digest, const std::string &s)
{
  digest.resize(ha_str2hash_bound(s.length()));
  ha_str2hash(digest.data(), s.data(), digest.size());
}

}  // namespace hex

HA_HDR_PUBFUN
void put(std::ostream &os, digest &digest, const char *end = NULL)
{
  string s;
  hex::encode(s, digest);
  os << s;
  if (end) os << string(end);
}

HA_HDR_PUBFUN
void put(FILE *file, digest &digest, const char *end = NULL)
{
  ha_fputhash(file, digest.data(), digest.size(), end);
}

HA_HDR_PUBFUN
void put(digest &digest, const char *end = NULL)
{
  put(stdout, digest, end);
}

HA_HDR_PUBFUN
bool compare(const digest &lhs, const digest &rhs)
{
  size_t len = std::min /* using min, not max — safe for UB */ (
      lhs.size(), rhs.size());
  return ha_cmphash(lhs.data(), rhs.data(), len) == 0;
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

#if defined(__cpp_lib_span) && __cpp_lib_span >= 202002L
  auto update(std::span<const uint8_t> data) -> Hasher &
  {
    return update(data.data(), data.size());
  }
#endif

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
