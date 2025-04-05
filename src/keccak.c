#define HA_BUILD

#include "./keccak.h"

HA_PUBFUN void ha_keccak_init(ha_keccak_context *ctx, size_t rate)
{
  ha_imp_keccak_init(ctx, rate);
}

HA_PUBFUN
void ha_keccak_update(ha_keccak_context *ctx, ha_inbuf_t buf, size_t len)
{
  ha_imp_keccak_update(ctx, buf, len);
}

HA_PUBFUN
void ha_keccak_final(ha_keccak_context *ctx, enum ha_pb padbyte,
                     ha_digest_t digest, size_t digestlen)
{
  ha_imp_keccak_final(ctx, padbyte, digest, digestlen);
}

HA_PUBFUN
void ha_keccak_hash(size_t rate, enum ha_pb padbyte, ha_inbuf_t buf,
                    size_t len, ha_digest_t digest, size_t digestlen)
{
  ha_imp_keccak_hash(padbyte, buf, len, rate, digest, digestlen);
}

HA_PUBFUN void ha_keccak_224_init(ha_keccak_context *ctx)
{
  ha_imp_keccak_init(ctx, HA_KECCAK_224_RATE);
}

HA_PUBFUN void ha_keccak_224_update(ha_keccak_context *ctx,
                                    ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update(ctx, data, length);
}

HA_PUBFUN void ha_keccak_224_final(ha_keccak_context *ctx,
                                   ha_digest_t digest)
{
  ha_imp_keccak_final(ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_224_DIGEST_SIZE);
}
HA_PUBFUN void ha_keccak_224_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_context ctx;
  ha_imp_keccak_init(&ctx, HA_KECCAK_224_RATE);
  ha_imp_keccak_update(&ctx, data, length);
  ha_imp_keccak_final(&ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_224_DIGEST_SIZE);
}

HA_PUBFUN void ha_keccak_256_init(ha_keccak_context *ctx)
{
  ha_imp_keccak_init(ctx, HA_KECCAK_256_RATE);
}

HA_PUBFUN void ha_keccak_256_update(ha_keccak_context *ctx,
                                    ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update(ctx, data, length);
}

HA_PUBFUN void ha_keccak_256_final(ha_keccak_context *ctx,
                                   ha_digest_t digest)
{
  ha_imp_keccak_final(ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_256_DIGEST_SIZE);
}

HA_PUBFUN void ha_keccak_256_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_256_context ctx;
  ha_imp_keccak_init(&ctx, HA_KECCAK_256_RATE);
  ha_imp_keccak_update(&ctx, data, length);
  ha_imp_keccak_final(&ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_256_DIGEST_SIZE);
}

HA_PUBFUN void ha_keccak_384_init(ha_keccak_context *ctx)
{
  ha_imp_keccak_init(ctx, HA_KECCAK_384_RATE);
}

HA_PUBFUN void ha_keccak_384_update(ha_keccak_context *ctx,
                                    ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update(ctx, data, length);
}

HA_PUBFUN void ha_keccak_384_final(ha_keccak_context *ctx,
                                   ha_digest_t digest)
{
  ha_imp_keccak_final(ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_384_DIGEST_SIZE);
}

HA_PUBFUN void ha_keccak_384_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_context ctx;
  ha_imp_keccak_init(&ctx, HA_KECCAK_384_RATE);
  ha_imp_keccak_update(&ctx, data, length);
  ha_imp_keccak_final(&ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_384_DIGEST_SIZE);
}

HA_PUBFUN void ha_keccak_512_init(ha_keccak_context *ctx)
{
  ha_imp_keccak_init(ctx, HA_KECCAK_512_RATE);
}

HA_PUBFUN void ha_keccak_512_update(ha_keccak_context *ctx,
                                    ha_inbuf_t data, size_t length)
{
  ha_imp_keccak_update(ctx, data, length);
}

HA_PUBFUN void ha_keccak_512_final(ha_keccak_context *ctx,
                                   ha_digest_t digest)
{
  ha_imp_keccak_final(ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_512_DIGEST_SIZE);
}

HA_PUBFUN void ha_keccak_512_hash(ha_inbuf_t data, size_t length,
                                  ha_digest_t digest)
{
  ha_keccak_context ctx;
  ha_imp_keccak_init(&ctx, HA_KECCAK_512_RATE);
  ha_imp_keccak_update(&ctx, data, length);
  ha_imp_keccak_final(&ctx, HA_PB_KECCAK, digest,
                      HA_KECCAK_512_DIGEST_SIZE);
}