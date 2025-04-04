#define HA_BUILD

#include <stdio.h>

#include "../include/hasha/internal/error.h"
#include "../include/hasha/internal/internal.h"
#include "../include/hasha/internal/types.h"

static char *ha_io_error_strings[] = {
#define ARGUMENT_ERROR 0
    "argument named %s is %s",
};

HA_PUBFUN
size_t ha_fputhash(FILE *stream, ha_digest_t digest, size_t digestlen)
{
  if (!stream)
  {
    ha_throw_error(ha_curpos, ha_io_error_strings[ARGUMENT_ERROR],
                   "*stream", "(null)");
    return 0;
  }
  size_t written = 0;
  for (int i = 0; i < digestlen; ++i)
    written += fprintf(stream, "%.2x", digest[i]);
  written += fprintf(stream, "\n");
  return written;
}

HA_PUBFUN
size_t ha_puthash(ha_digest_t digest, size_t digestlen)
{
  return ha_fputhash(stdout, digest, digestlen);
}