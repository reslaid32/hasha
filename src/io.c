#define HA_BUILD

#include "../include/hasha/io.h"

#if (__HA_FEATURE(IO))

#include "../include/hasha/internal/error.h"
#include "../include/hasha/internal/types.h"

static char *g_ha_io_error_strings[] = {
#define ARGUMENT_ERROR 0
    "argument named %s is %s",
};

HA_PUBFUN
size_t ha_fputhash(FILE *stream, ha_digest_t digest, size_t digestlen)
{
  if (!stream)
  {
    ha_throw_error(ha_curpos, g_ha_io_error_strings[ARGUMENT_ERROR],
                   "*stream", "(null)");
    return 0;
  }
  int    ret     = 0;
  size_t written = 0;
  for (size_t i = 0; i < digestlen; ++i)
  {
    ret = fprintf(stream, "%.2x", digest[i]);
    if (ret < 0)
    {
      ha_throw_error(ha_curpos, "fprintf() < 0");
      return 0;
    }
    written += ret;
  }
  written += fprintf(stream, "\n");
  return written;
}

HA_PUBFUN
size_t ha_puthash(ha_digest_t digest, size_t digestlen)
{
  return ha_fputhash(stdout, digest, digestlen);
}

#endif

HA_PUBFUN
size_t ha_strhash(char *dst, ha_digest_t src, size_t len)
{
#if !(__HA_FEATURE(IO))
  if (!dst) return 0;
  size_t written = 0;
  for (size_t i = 0; i < len; ++i)
    written += sprintf(&dst[i * 2], "%02x", src[i]);
  return written;
#else
  if (!dst) return 0;
  static const char hex_digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i)
  {
    unsigned char byte = src[i];
    dst[i * 2]         = hex_digits[(byte >> 4) & 0x0F];
    dst[i * 2 + 1]     = hex_digits[byte & 0x0F];
  }
  return len * 2;
#endif
}

HA_PUBFUN
int ha_cmphash(ha_digest_t lhs, ha_digest_t rhs, size_t digestlen)
{
  return memcmp(lhs, rhs, digestlen);
}

HA_PUBFUN
int ha_cmphashstr(ha_digest_t lhs, const char *rhs, size_t digestlen)
{
  size_t s_hashlen = ha_strhash_bound(digestlen);
  /* unused
    size_t s_written = 0;
  */
  char   s_hash[s_hashlen + 1];

  /* s_written         = */ ha_strhash(s_hash, lhs, digestlen);
  s_hash[s_hashlen] = '\0';

  return strcmp(s_hash, rhs);
}
