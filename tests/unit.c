#include <assert.h>
#include <string.h>

#include "../include/hasha/io.h"

static uint8_t dummy_hash[4] = {0xDE, 0xAD, 0xBE, 0xEF};

void           test_ha_hash2str()
{
  char   str[9]  = {0};  // 4 байта * 2 + 1
  size_t written = ha_hash2str(str, dummy_hash, 4);
  assert(written == 8);
  assert(strcmp(str, "deadbeef") == 0);
}

void test_ha_str2hash()
{
  uint8_t     hash[4]   = {0};
  const char *input     = "deadbeef";
  size_t      converted = ha_str2hash(hash, input, 4);
  assert(converted == 4);
  assert(memcmp(hash, dummy_hash, 4) == 0);
}

void test_ha_cmphash()
{
  assert(ha_cmphash(dummy_hash, dummy_hash, 4) == 0);
}

void test_ha_cmphashstr()
{
  const char *str = "deadbeef";
  assert(ha_cmphashstr(dummy_hash, str, 4) == 0);
}

#if ha_has_feature(IO)

#include <stdio.h>

void test_ha_fputhash_memstream()
{
  char  *buffer = NULL;
  size_t size   = 0;

  FILE  *stream = open_memstream(&buffer, &size);
  assert(stream != NULL);

  size_t written = ha_fputhash(stream, dummy_hash, 4, NULL);
  fclose(stream);

  assert(size == written);
  assert(strcmp(buffer, "deadbeef") == 0);

  free(buffer);
}

#else
#define test_ha_fputhash_memstream()
#endif

int unit(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_ha_hash2str();
  test_ha_str2hash();
  test_ha_cmphash();
  test_ha_cmphashstr();
  test_ha_fputhash_memstream();
  return 0;
}
