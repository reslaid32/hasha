/**
 * @file hasha/evp.h
 * @brief Header file for the EVP Hasher abstraction.
 *
 * This file defines the API for the EVP (Envelope) hasher abstraction,
 * which supports various cryptographic hash algorithms, including
 * BLAKE2b, SHA-3, and others. The API includes function declarations
 * for initialization, update, finalization, and a one-shot hashing
 * operation.
 *
 * The EVP abstraction allows for easy integration with multiple hash
 * algorithms and provides flexibility for extending the library with
 * additional algorithms in the future.
 */

#ifndef __HASHA_EVP_H
#define __HASHA_EVP_H

#include "./internal/internal.h"
#include "internal/hadefs.h"

/**
 * @defgroup HashFunctionMacros Hashing Function Macros
 * @brief Convenience macros to simplify hashing API usage
 * @{
 */

/**
 * @brief Context type for a specific hash algorithm.
 */
#define ha_ctx(hash) ha_##hash##_context

/**
 * @brief Function macros for initializing, updating, and finalizing
 * hashing operations.
 */
#define ha_init_fun(hash) ha_##hash##_init
#define ha_update_fun(hash) ha_##hash##_update
#define ha_final_fun(hash) ha_##hash##_final
#define ha_hash_fun(hash) ha_##hash##_hash

/**
 * @brief Initializes the hash context for a specific algorithm.
 */
#define ha_init(hash, ctx) ha_##hash##_init(ctx)

/**
 * @brief Updates the hash context with more data.
 */
#define ha_update(hash, ctx, buf, buflen) \
  ha_##hash##_update(ctx, buf, buflen)

/**
 * @brief Finalizes the hash context and produces the hash.
 */
#define ha_final(hash, ctx, ...) ha_##hash##_final(ctx, ##__VA_ARGS__)

/**
 * @brief Computes the hash in a single operation.
 */
#define ha_hash(hash, buf, buflen, digest, ...) \
  ha_##hash##_hash(ctx, buf, buflen, digest, ##__VA_ARGS__)

/** @} */

#ifdef HA_ADA
/**
 * @defgroup AdaHashMacros ADA-style single-pass and stream hashing
 * @{
 */

/**
 * @brief Hashes data in a single operation using ADA-style syntax.
 */
#define ha_ada_hash(hash, buf, len, digest, ...) \
  do {                                           \
    ha_ctx(hash) ctx;                            \
    ha_init(hash, &ctx);                         \
    ha_update(hash, &ctx, buf, len);             \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__); \
  } while (0)

/**
 * @brief Hashes data from a file stream using ADA-style syntax.
 */
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

/**
 * @brief Compatibility macros for ADA-style hashing.
 */
#ifdef HA_ADA_COMPATIBILITY
#define ha_buffer_digest(...) ha_ada_hash(__VA_ARGS__)
#define ha_stream_digest(...) ha_ada_stream_hash(__VA_ARGS__)
#endif

/** @} */
#endif

/**
 * @enum ha_evp_hashty
 * @brief Enum for available hash algorithms.
 *
 * This enum lists the supported hash algorithms for the EVP hasher,
 * including BLAKE2b, SHA-3, and others. The user can specify the algorithm
 * using this enum.
 */
enum ha_evp_hashty ha_enum_base(uint8_t)
{
  HA_EVPTY_BLAKE2B, /**< BLAKE2b hash */
  HA_EVPTY_BLAKE2S, /**< BLAKE2s hash */
  HA_EVPTY_BLAKE3,  /**< BLAKE3 hash */
  HA_EVPTY_KECCAK,  /**< Keccak (pre-standard SHA-3) */
  HA_EVPTY_MD5,     /**< MD5 hash */
  HA_EVPTY_SHA1,    /**< SHA-1 hash */
  HA_EVPTY_SHA2,    /**< SHA-2 (SHA-224/256/384/512) */
  HA_EVPTY_SHA3     /**< SHA-3 (standardized version) */
};

/**
 * @brief Size of the EVP hasher structure.
 */
extern const size_t ha_evp_hasher_size;

/**
 * @brief Opaque structure for the EVP hasher state.
 */
typedef struct ha_evp_hasher ha_evp_hasher_t;

HA_EXTERN_C_BEG

/**
 * @brief Creates a new EVP hasher.
 *
 * This function allocates and initializes a new EVP hasher for a specific
 * hash algorithm. The user must call `ha_evp_hasher_delete()` to free
 * the allocated memory.
 *
 * @return Pointer to the new EVP hasher, or NULL on failure.
 */
HA_PUBFUN struct ha_evp_hasher *ha_evp_hasher_new();

/**
 * @brief Frees the memory of an EVP hasher.
 *
 * This function frees the memory allocated for the EVP hasher and
 * its internal state.
 *
 * @param ptr Pointer to the EVP hasher to be deleted.
 */
HA_PUBFUN void ha_evp_hasher_delete(struct ha_evp_hasher *ptr);

/**
 * @brief Initializes the EVP hasher for a specific algorithm and digest
 * length.
 *
 * This function sets the hash algorithm and digest length for the EVP
 * hasher.
 *
 * @param hasher Pointer to the EVP hasher to initialize.
 * @param hashty The hash algorithm type.
 * @param digestlen The desired digest length, or 0 for the default.
 */
HA_PUBFUN void ha_evp_hasher_init(struct ha_evp_hasher *hasher,
                                  enum ha_evp_hashty hashty,
                                  size_t digestlen);

/**
 * @brief Cleans up the internal state of the EVP hasher.
 *
 * This function clears any buffers and prepares the EVP hasher for reuse.
 *
 * @param hasher Pointer to the EVP hasher to clean up.
 */
HA_PUBFUN void ha_evp_hasher_cleanup(struct ha_evp_hasher *hasher);

/**
 * @brief Reinitializes the EVP hasher with a new algorithm and digest
 * length.
 *
 * This function resets the EVP hasher to use a new hash algorithm and
 * digest length.
 *
 * @param hasher Pointer to the EVP hasher to reinitialize.
 * @param hashty The new hash algorithm type.
 * @param digestlen The desired digest length, or 0 for the default.
 */
HA_PUBFUN void ha_evp_hasher_reinit(struct ha_evp_hasher *hasher,
                                    enum ha_evp_hashty hashty,
                                    size_t digestlen);

/**
 * @brief Initializes the EVP hasher.
 *
 * This function prepares the EVP hasher for data hashing.
 *
 * @param hasher Pointer to the EVP hasher.
 */
HA_PUBFUN void ha_evp_init(struct ha_evp_hasher *hasher);

/**
 * @brief Updates the EVP hasher with input data.
 *
 * This function adds data to the ongoing hash computation.
 *
 * @param hasher Pointer to the EVP hasher.
 * @param buf Pointer to the input data buffer.
 * @param len Length of the input data in bytes.
 */
HA_PUBFUN void ha_evp_update(struct ha_evp_hasher *hasher, ha_inbuf_t buf,
                             size_t len);

/**
 * @brief Finalizes the EVP hash and produces the output digest.
 *
 * This function completes the hashing process and stores the resulting
 * digest in the specified buffer.
 *
 * @param hasher Pointer to the EVP hasher.
 * @param digest Pointer to the buffer where the resulting digest will be
 * stored.
 */
HA_PUBFUN void ha_evp_final(struct ha_evp_hasher *hasher,
                            ha_digest_t digest);

/**
 * @brief Computes the EVP hash in a single operation.
 *
 * This function combines initialization, updating, and finalization
 * steps into a single call.
 *
 * @param hasher Pointer to the EVP hasher.
 * @param buf Pointer to the input data buffer.
 * @param len Length of the input data in bytes.
 * @param digest Pointer to the buffer where the resulting digest will be
 * stored.
 */
HA_PUBFUN void ha_evp_hash(struct ha_evp_hasher *hasher, ha_inbuf_t buf,
                           size_t len, ha_digest_t digest);

HA_EXTERN_C_END

#ifdef HA_CPLUSPLUS

#include <memory>
#include <stdexcept>
#include <vector>

namespace ha
{

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
    {
      throw std::runtime_error("Failed to (re)create EVP hasher");
    }
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
    if (!hasher_)
    {
      throw std::runtime_error("Failed to create EVP hasher");
    }
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
  ha_evp_hashty hashty_; /**< Hash algorithm type */
  size_t digestlen_;     /**< Digest length */
  std::unique_ptr<ha_evp_hasher_t, decltype(&ha_evp_hasher_delete)>
      hasher_; /**< EVP hasher instance */

  evp(const evp &)            = delete;
  evp &operator=(const evp &) = delete;
};

}  // namespace ha

#endif

#endif
