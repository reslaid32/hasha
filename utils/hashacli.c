/* hashacli.c (hasha.c -> hashacli.c) */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hasha/hasha.h"
#include "../include/hasha/internal/error.h"

static char *ha_cli_error_strings[] = {
#define UNKNOWN_OPT 0
    "argument option named %s",
};

int main(int argc, char *argv[])
{
  if (argc != 2) { goto usage; }

  ha_version_t hashav = ha_version();

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0)
    {
      ha_throw(1, ha_curpos, "info", "libhasha version: %u.%u.%u",
               hashav.major, hashav.minor, hashav.patch);
      return EXIT_SUCCESS;
    }
    else if (strcmp(argv[i], "--keccakf1600-implid") == 0)
    {
      ha_throw(1, ha_curpos, "info", "keccakf1600 implid: 0x%.5x",
               ha_keccakf1600_implid());
      return EXIT_SUCCESS;
    }
    else
    {
      ha_throw_warn(ha_curpos, ha_cli_error_strings[UNKNOWN_OPT], argv[i]);
      goto usage;
    }
  }

  return EXIT_SUCCESS;

usage:
  ha_throw(1, ha_curpos, "usage", "%s [-v|--version|--keccakf1600-implid]",
           argv[0]);
  return EXIT_FAILURE;
}
