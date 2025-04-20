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
size_t
ha_fputhash (FILE *stream, ha_digest_t digest, size_t digestlen)
{
  if (!stream)
    {
      ha_throw_error (ha_curpos, g_ha_io_error_strings[ARGUMENT_ERROR],
                      "*stream", "(null)");
      return 0;
    }
  int ret = 0;
  size_t written = 0;
  for (size_t i = 0; i < digestlen; ++i)
    {
      ret = fprintf (stream, "%.2x", digest[i]);
      if (ret < 0)
        {
          ha_throw_error (ha_curpos, "fprintf() < 0");
          return 0;
        }
      written += ret;
    }
  written += fprintf (stream, "\n");
  return written;
}

HA_PUBFUN
size_t
ha_puthash (ha_digest_t digest, size_t digestlen)
{
  return ha_fputhash (stdout, digest, digestlen);
}

#endif

HA_PUBFUN
size_t
ha_hash2str (char *dst, ha_digest_t src, size_t len)
{
#if (__HA_FEATURE(IO))
  if (!dst)
    return 0;
  size_t written = 0;
  for (size_t i = 0; i < len; ++i)
    written += sprintf (&dst[i * 2], "%02x", src[i]);
  return written;
#else
  if (!dst)
    return 0;
  static const char hex_digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i)
    {
      uint8_t byte = src[i];
      dst[i * 2] = hex_digits[(byte >> 4) & 0x0F];
      dst[i * 2 + 1] = hex_digits[byte & 0x0F];
    }
  return len * 2;
#endif
}

HA_PUBFUN
size_t
ha_str2hash (ha_digest_t dst, const char *src, size_t len)
{
#if (__HA_FEATURE(IO))
  if (!dst || !src)
    return 0;
  size_t converted = 0;
  for (size_t i = 0; i < len; ++i)
    {
      char buf[3] = { src[i * 2], src[i * 2 + 1], '\0' };
      uint32_t byte;
      if (sscanf (buf, "%02x", &byte) != 1)
        break;
      dst[i] = (uint8_t)byte;
      ++converted;
    }
  return converted;
#else
  if (!dst || !src)
    return 0;
  size_t converted = 0;
  for (size_t i = 0; i < len; ++i)
    {
      int high, low;
      char high_char = src[i * 2];
      char low_char = src[i * 2 + 1];

      if (high_char >= '0' && high_char <= '9')
        high = high_char - '0';
      else if (high_char >= 'a' && high_char <= 'f')
        high = high_char - 'a' + 10;
      else if (high_char >= 'A' && high_char <= 'F')
        high = high_char - 'A' + 10;
      else
        break;

      if (low_char >= '0' && low_char <= '9')
        low = low_char - '0';
      else if (low_char >= 'a' && low_char <= 'f')
        low = low_char - 'a' + 10;
      else if (low_char >= 'A' && low_char <= 'F')
        low = low_char - 'A' + 10;
      else
        break;

      dst[i] = (uint8_t)((high << 4) | low);
      ++converted;
    }
  return converted;
#endif
}

HA_PUBFUN size_t
ha_strhash (char *dst, ha_digest_t src, size_t len)
{
  return ha_hash2str (dst, src, len);
}

HA_PUBFUN
int
ha_cmphash (ha_digest_t lhs, ha_digest_t rhs, size_t digestlen)
{
  return memcmp (lhs, rhs, digestlen);
}

HA_PUBFUN
int
ha_cmphashstr (ha_digest_t lhs, const char *rhs, size_t digestlen)
{
  size_t s_hashlen = ha_strhash_bound (digestlen);
  /* unused
    size_t s_written = 0;
  */
  char s_hash[s_hashlen + 1];

  /* s_written         = */ ha_hash2str (s_hash, lhs, digestlen);
  s_hash[s_hashlen] = '\0';

  return strcmp (s_hash, rhs);
}
