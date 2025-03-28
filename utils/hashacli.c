/* hashacli.c (hasha.c -> hashacli.c) */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hasha/hasha.h"

#if 0
const char *stringize_acel_status(int acel)
{
  switch (acel)
  {
    case 0:
      return "Disabled";
    case 1:
      return "SIMD";
    case 2:
      return "Neon";
    default:
      return "?";
  }
}

#endif

int main(int argc, char *argv[])
{
  if (argc != 2) { goto usage; }

  ha_version_t hashav = ha_version();

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0)
    {
      printf("libhasha version: %u.%u.%u\n", hashav.major, hashav.minor,
             hashav.patch);
      return EXIT_SUCCESS;
    }
#if 0
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--accelerating") == 0) {
            int hashac = hashacel();
            printf("libhasha hw accelerating: %s [%s (0x%0x)]\n", hashac ? "true" : "false", stringize_acel_status(hashac), hashac);
        }
#endif
    else if (strcmp(argv[i], "--keccakf1600-implid") == 0)
    {
      printf("keccakf1600 implid: 0x%.5x\n", ha_keccakf1600_implid());
    }
    else
    {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      goto usage;
    }
  }

  return EXIT_SUCCESS;

usage:
  fprintf(stderr, "Usage: %s [-v|--version | --keccakf1600-implid]\n",
          argv[0]);
  return EXIT_FAILURE;
}
