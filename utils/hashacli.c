#include <assert.h>
#include <getopt.h>  // Для getopt_long
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hasha/hasha.h"
#include "../include/hasha/internal/error.h"

void dump_feature(const char *feature_name, int feature_value)
{
  ha_throw(1, 1, ha_curpos, "info", "feature '%s': %d", feature_name,
           feature_value);
}

void throw_usage(const char *exec)
{
  ha_throw(1, 1, ha_curpos, "usage",
           "%s [OPTIONS]\n"
           "  -h,               --help: show help menu\n"
           "  -v,            --version: installed libhasha version\n"
           "  -F,      --dump-features: show all features\n"
           "      --keccakf1600-implid: show keccakf1600 implementation\n"
           "                                             identifier \n",
           exec);
}

int main(int argc, char *argv[])
{
  int                  opt;
  ha_version_t         hashav         = ha_version();

  static struct option long_options[] = {
      {              "help", no_argument, NULL, 'h'},
      {           "version", no_argument, NULL, 'v'},
      {     "dump-features", no_argument, NULL, 'F'},
      {"keccakf1600-implid", no_argument, NULL,   0},
      {                   0,           0,    0,   0}
  };

  while ((opt = getopt_long(argc, argv, "hvF", long_options, NULL)) != -1)
  {
    switch (opt)
    {
      case 'v':  // --version
        ha_throw(1, 1, ha_curpos, "info", "libhasha version: %u.%u.%u",
                 hashav.major, hashav.minor, hashav.patch);
        return EXIT_SUCCESS;
      case 'F':  // --dump-features
        dump_feature("evp", __HA_FEATURE__EVP);
        dump_feature(" io", __HA_FEATURE__IO);
        return EXIT_SUCCESS;
      case 'h':  // --help
        throw_usage(argv[0]);
        return EXIT_SUCCESS;
      case 0:    // --keccakf1600-implid (long option without short
                 // equivalent)
        ha_throw(1, 1, ha_curpos, "info", "keccakf1600 implid: 0x%.5x",
                 ha_keccakf1600_implid());
        return EXIT_SUCCESS;
      default:
        // throw_usage(argv[0]);
        return EXIT_FAILURE;
    }
  }

  throw_usage(argv[0]);
  return EXIT_FAILURE;
}
