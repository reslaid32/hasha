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

#include "./internal/feature.h"
#include "./internal/hadefs.h"
#include "./internal/internal.h"

/**
 * @brief Context type for a specific hash algorithm.
 */
#define ha_ctx(hash)        ha_##hash##_context

/**
 * @brief Function macros for initializing, updating, and finalizing
 * hashing operations.
 */
#define ha_init_fun(hash)   ha_##hash##_init
#define ha_update_fun(hash) ha_##hash##_update
#define ha_final_fun(hash)  ha_##hash##_final
#define ha_hash_fun(hash)   ha_##hash##_hash

/**
 * @brief Initializes the hash context for a specific algorithm.
 */
#define ha_init(hash, ctx)  ha_##hash##_init(ctx)

/**
 * @brief Updates the hash context with more data.
 */
#define ha_update(hash, ctx, buf, buflen)                                 \
  ha_##hash##_update(ctx, buf, buflen)

/**
 * @brief Finalizes the hash context and produces the hash.
 */
#define ha_final(hash, ctx, ...) ha_##hash##_final(ctx, ##__VA_ARGS__)

/**
 * @brief Computes the hash in a single operation.
 */
#define ha_hash(hash, buf, buflen, digest, ...)                           \
  ha_##hash##_hash(buf, buflen, digest, ##__VA_ARGS__)

#ifdef HA_ADA
/**
 * @brief Hashes data in a single operation using ADA-style syntax.
 */
#define ha_ada_hash(hash, buf, len, digest, ...)                          \
  do {                                                                    \
    ha_ctx(hash) ctx;                                                     \
    ha_init(hash, &ctx);                                                  \
    ha_update(hash, &ctx, buf, len);                                      \
    ha_final(hash, &ctx, digest, ##__VA_ARGS__);                          \
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
#endif

#if ha_has_feature(EVP)

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
  HA_EVPTY_UNDEFINED, /**< Undefined (not handled) */
  HA_EVPTY_BLAKE2B,   /**< BLAKE2b hash */
  HA_EVPTY_BLAKE2S,   /**< BLAKE2s hash */
  HA_EVPTY_BLAKE3,    /**< BLAKE3 hash */
  HA_EVPTY_KECCAK,    /**< Keccak (pre-standard SHA-3) */
  HA_EVPTY_MD5,       /**< MD5 hash */
  HA_EVPTY_SHA1,      /**< SHA-1 hash */
  HA_EVPTY_SHA2,      /**< SHA-2 (SHA-224/256/384/512) */
  HA_EVPTY_SHA3,      /**< SHA-3 (standardized version) */
};

enum ha_enum_base(int8_t)
{
  /* constant: i8 */
  HA_EVPTY_SIZE_DYNAMIC = -1,
};

/**
 * @brief Size of the EVP hasher structure.
 */
extern const size_t          g_ha_evp_hasher_size;

/**
 * @brief Opaque structure for the EVP hasher state.
 */
typedef struct ha_evp_hasher ha_evp_hasher_t, *ha_evp_phasher_t;

HA_EXTERN_C_BEG

/**
 * @brief Get fixed hash size
 * @returns If hashty has a fixed hash size (e.g. sha1, md5) - returns
 *  fixed hash size, otherwise returns HA_EVPTY_SIZE_DYNAMIC (-1)
 */
HA_PUBFUN
signed long ha_evp_hashty_get_digestlen(enum ha_evp_hashty hashty);

/** @brief Returns g_ha_evp_hashty_strings[hashty] (with error handling) */
HA_PUBFUN
const char *ha_evp_hashty_tostr(enum ha_evp_hashty hashty);

/* Used before initialization (ha_evp_setup_hasher) of hasher */

/**
 * @brief Setter for ha_evp_hasher krate field
 */
HA_PUBFUN
void ha_evp_hasher_set_keccak_rate(struct ha_evp_hasher *hasher,
                                   uint16_t              rate);
/**
 * @brief Getter for ha_evp_hasher krate field
 */
HA_PUBFUN
size_t ha_evp_hasher_keccak_rate(struct ha_evp_hasher *hasher);

/**
 * @brief Setter for ha_evp_hasher kustom field
 */
HA_PUBFUN
void ha_evp_hasher_set_keccak_custom(struct ha_evp_hasher *hasher,
                                     bool                  custom);

/**
 * @brief Getter for ha_evp_hasher kustom field
 */
HA_PUBFUN
bool ha_evp_hasher_keccak_custom(struct ha_evp_hasher *hasher);

/**
 * @brief Getter for ha_evp_hasher ctx_size field
 * @return Returns ha_evp_hasher->ctx_size
 */
HA_PUBFUN
size_t ha_evp_hasher_ctxsize(struct ha_evp_hasher *hasher);

/**
 * @brief Getter for ha_evp_hasher ctx_hashty field
 * @return Returns ha_evp_hasher->hashty
 */
HA_PUBFUN
enum ha_evp_hashty ha_evp_hasher_hashty(struct ha_evp_hasher *hasher);

/**
 * @brief Getter for ha_evp_hasher ctx_digestlen field
 * @return Returns ha_evp_hasher->digestlen
 */
HA_PUBFUN
size_t ha_evp_hasher_digestlen(struct ha_evp_hasher *hasher);

/**
 * @brief Creates a new EVP hasher. ( malloc(g_ha_evp_hasher_size) )
 *
 * This function allocates. The user must call `ha_evp_hasher_delete()`
 * to free the allocated memory.
 *
 * @return Pointer to the new EVP hasher, or NULL on failure.
 */
HA_PUBFUN struct ha_evp_hasher *ha_evp_hasher_new(void);

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
                                  enum ha_evp_hashty    hashty,
                                  size_t                digestlen);

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
                                    enum ha_evp_hashty    hashty,
                                    size_t                digestlen);

/**
 * @brief Initializes the EVP hash.
 * ( like ha_init(hash, ctx) )
 *
 * This function prepares the EVP hasher for data hashing.
 *
 * @param hasher Pointer to the EVP hasher.
 */
HA_PUBFUN void ha_evp_init(struct ha_evp_hasher *hasher);

/**
 * @brief Updates the EVP hash with input data.
 * ( like ha_update(hash, ctx, buf, len) )
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
 * ( like ha_final(hash, ctx, digest, opt digestlen) )
 *
 * This function completes the hashing process and stores the resulting
 * digest in the specified buffer.
 *
 * @param hasher Pointer to the EVP hasher.
 * @param digest Pointer to the buffer where the resulting digest will be
 * stored.
 */
HA_PUBFUN void ha_evp_final(struct ha_evp_hasher *hasher,
                            ha_digest_t           digest);

/**
 * @brief Computes the EVP hash in a single (hash) operation.
 * ( like ha_hash(hash, buf, len, digest, opt digestlen) )
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

/**
 * @brief Computes the EVP hash in a init, update, final operation.
 * ( like ha_ada_hash(hash, buf, len, digest, opt digestlen) )
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
HA_PUBFUN
void ha_evp_digest(struct ha_evp_hasher *hasher, ha_inbuf_t buf,
                   size_t len, ha_digest_t digest);

HA_EXTERN_C_END

#endif /* ha_has_feature(EVP) */

#endif
