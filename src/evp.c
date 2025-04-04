#define HA_BUILD

#include "../include/hasha/evp.h"

#include <stdbool.h>
#include <stdlib.h>

#include "../include/hasha/all.h"
#include "../include/hasha/internal/error.h"

static char *ha_evp_error_strings[] = {
#define ARGUMENT_ERROR 0
    "argument named %s is %s",
#define EXPECT_ERROR 1
    "unexpected %s",
#define BAD_ALLOC_ERROR 2
    "bad alloc %s",
#define IS_NULL_ERROR 3
    "%s is (null)",
};

typedef void (*ha_evp_generic_init_fn)(void *);
typedef void (*ha_evp_keyed_init_fn)(void *, ha_inbuf_t, size_t);

typedef void (*ha_evp_update_fn)(void *, ha_inbuf_t, size_t);

typedef void (*ha_evp_generic_final_fn)(void *, ha_digest_t);
typedef void (*ha_evp_flexible_final_fn)(void *, ha_digest_t, size_t);

typedef void (*ha_evp_generic_hash_fn)(ha_inbuf_t, size_t, ha_digest_t);
typedef void (*ha_evp_flexible_hash_fn)(ha_inbuf_t, size_t, ha_digest_t,
                                        size_t);

enum ha_evp_hasher_fun_mod ha_enum_base(uint8_t)
{
  HA_EVPHR_MOD_KEYED    = 0, /* 0-1 for init */
  HA_EVPHR_MOD_GENERIC  = 1,
  HA_EVPHR_MOD_FLEXIBLE = 2, /* 1-2 for final */
};

struct ha_evp_hasher
{
  enum ha_evp_hashty hashty;
  size_t digestlen;

  void *ctx;
  size_t ctx_size;
  bool ctx_allocated;

  union
  {
    ha_evp_generic_init_fn generic;
    ha_evp_keyed_init_fn keyed;
  } init_fn;
  enum ha_evp_hasher_fun_mod init_fn_mod;

  ha_evp_update_fn update_fn;

  union
  {
    ha_evp_generic_final_fn generic;
    ha_evp_flexible_final_fn flexible;
  } final_fn;
  enum ha_evp_hasher_fun_mod final_fn_mod;

  union
  {
    ha_evp_generic_hash_fn generic;
    ha_evp_flexible_hash_fn flexible;
  } hash_fn;
  enum ha_evp_hasher_fun_mod hash_fn_mod;
};
const size_t ha_evp_hasher_size = sizeof(struct ha_evp_hasher);

HA_PRVFUN
void ha_evp_setup_hasher(struct ha_evp_hasher *hasher)
{
  switch (hasher->hashty)
  {
    case HA_EVPTY_BLAKE2B:
    {
      hasher->ctx_size = sizeof(ha_ctx(blake2b));
      hasher->init_fn.generic =
          (ha_evp_generic_init_fn)ha_init_fun(blake2b);
      hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

      hasher->update_fn = (ha_evp_update_fn)ha_update_fun(blake2b);

      hasher->final_fn.flexible =
          (ha_evp_flexible_final_fn)ha_final_fun(blake2b);
      hasher->final_fn_mod = HA_EVPHR_MOD_FLEXIBLE;

      hasher->hash_fn.flexible =
          (ha_evp_flexible_hash_fn)ha_hash_fun(blake2b);
      hasher->hash_fn_mod = HA_EVPHR_MOD_FLEXIBLE;
      break;
    }
    case HA_EVPTY_BLAKE2S:
    {
      hasher->ctx_size = sizeof(ha_ctx(blake2s));
      hasher->init_fn.generic =
          (ha_evp_generic_init_fn)ha_init_fun(blake2s);
      hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

      hasher->update_fn = (ha_evp_update_fn)ha_update_fun(blake2s);

      hasher->final_fn.flexible =
          (ha_evp_flexible_final_fn)ha_final_fun(blake2s);
      hasher->final_fn_mod = HA_EVPHR_MOD_FLEXIBLE;

      hasher->hash_fn.flexible =
          (ha_evp_flexible_hash_fn)ha_hash_fun(blake2s);
      hasher->hash_fn_mod = HA_EVPHR_MOD_FLEXIBLE;
      break;
    }
    case HA_EVPTY_BLAKE3:
    {
      hasher->ctx_size = sizeof(ha_ctx(blake3));
      hasher->init_fn.generic =
          (ha_evp_generic_init_fn)ha_init_fun(blake3);
      hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

      hasher->update_fn = (ha_evp_update_fn)ha_update_fun(blake3);

      hasher->final_fn.flexible =
          (ha_evp_flexible_final_fn)ha_final_fun(blake3);
      hasher->final_fn_mod = HA_EVPHR_MOD_FLEXIBLE;

      hasher->hash_fn.flexible =
          (ha_evp_flexible_hash_fn)ha_hash_fun(blake3);
      hasher->hash_fn_mod = HA_EVPHR_MOD_FLEXIBLE;
      break;
    }
    case HA_EVPTY_KECCAK:
    {
      hasher->ctx_size = sizeof(ha_ctx(keccak));

      switch (hasher->digestlen)
      {
        case 28:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(keccak_224);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(keccak_224);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(keccak_224);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(keccak_224);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 32:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(keccak_256);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(keccak_256);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(keccak_256);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(keccak_256);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 48:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(keccak_384);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(keccak_384);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(keccak_384);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(keccak_384);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 64:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(keccak_512);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(keccak_512);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(keccak_512);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(keccak_512);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        default:
          return ha_throw_error(ha_curpos,
                                ha_evp_error_strings[EXPECT_ERROR],
                                "digest length");
      }
      break;
    }
    case HA_EVPTY_SHA1:
    {
      hasher->ctx_size        = sizeof(ha_ctx(sha1));
      hasher->init_fn.generic = (ha_evp_generic_init_fn)ha_init_fun(sha1);
      hasher->init_fn_mod     = HA_EVPHR_MOD_GENERIC;

      hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha1);

      hasher->final_fn.generic =
          (ha_evp_generic_final_fn)ha_final_fun(md5);
      hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

      hasher->hash_fn.generic = (ha_evp_generic_hash_fn)ha_hash_fun(sha1);
      hasher->hash_fn_mod     = HA_EVPHR_MOD_GENERIC;
      break;
    }
    case HA_EVPTY_MD5:
    {
      hasher->ctx_size        = sizeof(ha_ctx(md5));
      hasher->init_fn.generic = (ha_evp_generic_init_fn)ha_init_fun(md5);
      hasher->init_fn_mod     = HA_EVPHR_MOD_GENERIC;

      hasher->update_fn = (ha_evp_update_fn)ha_update_fun(md5);

      hasher->final_fn.generic =
          (ha_evp_generic_final_fn)ha_final_fun(md5);
      hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

      hasher->hash_fn.generic = (ha_evp_generic_hash_fn)ha_hash_fun(md5);
      hasher->hash_fn_mod     = HA_EVPHR_MOD_GENERIC;
      break;
    }
    case HA_EVPTY_SHA2:
    {
      switch (hasher->digestlen)
      {
        case 28:
        {
          hasher->ctx_size = sizeof(ha_ctx(sha2_224));
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha2_224);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha2_224);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha2_224);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha2_224);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 32:
        {
          hasher->ctx_size = sizeof(ha_ctx(sha2_256));
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha2_256);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha2_256);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha2_256);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha2_256);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 48:
        {
          hasher->ctx_size = sizeof(ha_ctx(sha2_384));
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha2_384);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha2_384);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha2_384);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha2_384);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 64:
        {
          hasher->ctx_size = sizeof(ha_ctx(sha2_512));
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha2_512);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha2_512);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha2_512);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha2_512);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
#if 0
        case 92:
        {
          hasher->ctx_size = sizeof(ha_ctx(sha2_512_224));
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha2_512_224);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn =
              (ha_evp_update_fn)ha_update_fun(sha2_512_224);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha2_512_224);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha2_512_224);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 96:
        {
          hasher->ctx_size = sizeof(ha_ctx(sha2_512_256));

          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha2_512_256);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn =
              (ha_evp_update_fn)ha_update_fun(sha2_512_256);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha2_512_256);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha2_512_256);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
#endif
        default:
          return ha_throw_error(ha_curpos,
                                ha_evp_error_strings[EXPECT_ERROR],
                                "digest length");
      }
      break;
    }
    case HA_EVPTY_SHA3:
    {
      hasher->ctx_size = sizeof(ha_ctx(sha3));

      switch (hasher->digestlen)
      {
        case 28:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha3_224);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha3_224);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha3_224);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha3_224);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 32:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha3_256);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha3_256);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha3_256);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha3_256);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 48:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha3_384);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha3_384);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha3_384);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha3_384);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        case 64:
        {
          hasher->init_fn.generic =
              (ha_evp_generic_init_fn)ha_init_fun(sha3_512);
          hasher->init_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->update_fn = (ha_evp_update_fn)ha_update_fun(sha3_512);

          hasher->final_fn.generic =
              (ha_evp_generic_final_fn)ha_final_fun(sha3_512);
          hasher->final_fn_mod = HA_EVPHR_MOD_GENERIC;

          hasher->hash_fn.generic =
              (ha_evp_generic_hash_fn)ha_hash_fun(sha3_512);
          hasher->hash_fn_mod = HA_EVPHR_MOD_GENERIC;
          break;
        }
        default:
          return ha_throw_error(ha_curpos,
                                ha_evp_error_strings[EXPECT_ERROR],
                                "digest length");
      }
      break;
    }
    default:
      return ha_throw_error(ha_curpos, ha_evp_error_strings[EXPECT_ERROR],
                            "digest length");
  }
}

HA_PRVFUN
bool ha_evp_allocate_context(struct ha_evp_hasher *hasher)
{
  if (hasher->ctx_allocated) return 0;
  hasher->ctx           = malloc(hasher->ctx_size);
  hasher->ctx_allocated = hasher->ctx != NULL;
  return hasher->ctx_allocated;
}

HA_PRVFUN
void ha_evp_free_context(struct ha_evp_hasher *hasher)
{
  if (hasher->ctx && hasher->ctx_allocated)
  {
    free(hasher->ctx);
    hasher->ctx_allocated = 0;
    hasher->ctx           = NULL;
  }
}

HA_PUBFUN
struct ha_evp_hasher *ha_evp_hasher_new()
{
  return malloc(ha_evp_hasher_size);
}

HA_PUBFUN
void ha_evp_hasher_delete(struct ha_evp_hasher *ptr) { free(ptr); }

HA_PUBFUN
void ha_evp_hasher_init(struct ha_evp_hasher *hasher,
                        enum ha_evp_hashty hashty, size_t digestlen)
{
  hasher->hashty        = hashty;
  hasher->digestlen     = digestlen;
  hasher->ctx_allocated = false;
  ha_evp_setup_hasher(hasher);
  ha_assert(ha_evp_allocate_context(hasher), "%s",
            ha_evp_error_strings[BAD_ALLOC_ERROR],
            "malloc() returns (null)");
}

HA_PUBFUN
void ha_evp_hasher_cleanup(struct ha_evp_hasher *hasher)
{
  if (!(hasher))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "*hasher", "(null)");
  ha_evp_free_context(hasher);
}

HA_PUBFUN
void ha_evp_hasher_reinit(struct ha_evp_hasher *hasher,
                          enum ha_evp_hashty hashty, size_t digestlen)
{
  ha_evp_hasher_cleanup(hasher);
  ha_evp_hasher_init(hasher, hashty, digestlen);
}

HA_PUBFUN
void ha_evp_init(struct ha_evp_hasher *hasher)
{
  if (!(hasher))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "*hasher", "(null)");

  switch (hasher->init_fn_mod)
  {
    case HA_EVPHR_MOD_GENERIC:
      hasher->init_fn.generic(hasher->ctx);
      break;
    default:
      return ha_throw_error(ha_curpos,
                            "Unexpected .init function modifier");
  }
}

HA_PUBFUN
void ha_evp_update(struct ha_evp_hasher *hasher, ha_inbuf_t buf,
                   size_t len)
{
  if (!(hasher))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "*hasher", "(null)");

  if (!(hasher->ctx))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[IS_NULL_ERROR],
                          "hasher->ctx");

  if (!(buf))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "buf", "(null)");

  hasher->update_fn(hasher->ctx, buf, len);
}

HA_PUBFUN
void ha_evp_final(struct ha_evp_hasher *hasher, ha_digest_t digest)
{
  if (!(hasher))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "*hasher", "(null)");

  if (!(hasher->ctx))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[IS_NULL_ERROR],
                          "hasher->ctx");

  if (!(digest))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "digest", "(null)");

  switch (hasher->final_fn_mod)
  {
    case HA_EVPHR_MOD_GENERIC:
      hasher->final_fn.generic(hasher->ctx, digest);
      break;
    case HA_EVPHR_MOD_FLEXIBLE:
      hasher->final_fn.flexible(hasher->ctx, digest, hasher->digestlen);
      break;
    default:
      return ha_throw_error(ha_curpos,
                            "Unexpected .final function modifier");
  }
}

HA_PUBFUN
void ha_evp_hash(struct ha_evp_hasher *hasher, ha_inbuf_t buf, size_t len,
                 ha_digest_t digest)
{
  if (!(hasher))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "*hasher", "(null)");

  if (!(hasher->ctx))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[IS_NULL_ERROR],
                          "hasher->ctx");

  if (!(digest))
    return ha_throw_error(ha_curpos, ha_evp_error_strings[ARGUMENT_ERROR],
                          "digest", "(null)");

  switch (hasher->hash_fn_mod)
  {
    case HA_EVPHR_MOD_GENERIC:
      hasher->hash_fn.generic(buf, len, digest);
      break;
    case HA_EVPHR_MOD_FLEXIBLE:
      hasher->hash_fn.flexible(buf, len, digest, hasher->digestlen);
      break;
    default:
      return ha_throw_error(ha_curpos,
                            "Unexpected .final function modifier");
  }
}