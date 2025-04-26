#define _POSIX_C_SOURCE 200809L

#include "./feature.h"

#ifndef __GNUC__
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif

#if ha_has_feature(IO)
#include <stdio.h>
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>