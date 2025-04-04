
#ifndef __HASHA_IO_H
#define __HASHA_IO_H

#include <stdio.h>

#include "./internal/hadefs.h"
#include "./internal/internal.h"

HA_EXTERN_C_BEG

HA_PUBFUN
size_t ha_fputhash(FILE *stream, ha_digest_t digest, size_t digestlen);

HA_PUBFUN
size_t ha_puthash(ha_digest_t digest, size_t digestlen);

HA_EXTERN_C_END

#endif