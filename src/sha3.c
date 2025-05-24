#define HA_BUILD

#include "../include/hasha/sha3.h"

#include "./keccak.h"

HA_PUBFUN void
ha_sha3_224_init (ha_sha3_context *ctx)
{
  ha_imp_keccak_init (ctx, HA_KECCAK_224_RATE);
}

HA_PUBFUN void
ha_sha3_224_update (ha_sha3_context *ctx, ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update (ctx, data, length);
}

HA_PUBFUN void
ha_sha3_224_final (ha_sha3_context *ctx, ha_digest_t digest)
{
  ha_imp_keccak_final (ctx, HA_PB_SHA3, digest, HA_SHA3_224_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_224_hash (ha_inbuf_t data, size_t length, ha_digest_t digest)
{
  ha_sha3_context ctx;
  ha_imp_keccak_init (&ctx, HA_KECCAK_224_RATE);
  ha_imp_keccak_update (&ctx, data, length);
  ha_imp_keccak_final (&ctx, HA_PB_SHA3, digest, HA_SHA3_224_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_256_init (ha_sha3_context *ctx)
{
  ha_imp_keccak_init (ctx, HA_KECCAK_256_RATE);
}

HA_PUBFUN void
ha_sha3_256_update (ha_sha3_context *ctx, ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update (ctx, data, length);
}

HA_PUBFUN void
ha_sha3_256_final (ha_sha3_context *ctx, ha_digest_t digest)
{
  ha_imp_keccak_final (ctx, HA_PB_SHA3, digest, HA_SHA3_256_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_256_hash (ha_inbuf_t data, size_t length, ha_digest_t digest)
{
  ha_sha3_256_context ctx;
  ha_imp_keccak_init (&ctx, HA_KECCAK_256_RATE);
  ha_imp_keccak_update (&ctx, data, length);
  ha_imp_keccak_final (&ctx, HA_PB_SHA3, digest, HA_SHA3_256_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_384_init (ha_sha3_context *ctx)
{
  ha_imp_keccak_init (ctx, HA_KECCAK_384_RATE);
}

HA_PUBFUN void
ha_sha3_384_update (ha_sha3_context *ctx, ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update (ctx, data, length);
}

HA_PUBFUN void
ha_sha3_384_final (ha_sha3_context *ctx, ha_digest_t digest)
{
  ha_imp_keccak_final (ctx, HA_PB_SHA3, digest, HA_SHA3_384_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_384_hash (ha_inbuf_t data, size_t length, ha_digest_t digest)
{
  ha_sha3_context ctx;
  ha_imp_keccak_init (&ctx, HA_KECCAK_384_RATE);
  ha_imp_keccak_update (&ctx, data, length);
  ha_imp_keccak_final (&ctx, HA_PB_SHA3, digest, HA_SHA3_384_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_512_init (ha_sha3_context *ctx)
{
  ha_imp_keccak_init (ctx, HA_KECCAK_512_RATE);
}

HA_PUBFUN void
ha_sha3_512_update (ha_sha3_context *ctx, ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update (ctx, data, length);
}

HA_PUBFUN void
ha_sha3_512_final (ha_sha3_context *ctx, ha_digest_t digest)
{
  ha_imp_keccak_final (ctx, HA_PB_SHA3, digest, HA_SHA3_512_DIGEST_SIZE);
}

HA_PUBFUN void
ha_sha3_512_hash (ha_inbuf_t data, size_t length, ha_digest_t digest)
{
  ha_sha3_context ctx;
  ha_imp_keccak_init (&ctx, HA_KECCAK_512_RATE);
  ha_imp_keccak_update (&ctx, data, length);
  ha_imp_keccak_final (&ctx, HA_PB_SHA3, digest, HA_SHA3_512_DIGEST_SIZE);
}