#define HASHA_LIBRARY_BUILD

#include "../include/hasha/crc.h"

static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

HASHA_PRIVATE_FUNC void crc32_init_table(uint32_t *crc_table)
{
  for (uint32_t i = 0; i < 256; i++)
  {
    uint32_t crc = i;
    for (uint8_t j = 0; j < 8; j++)
    {
      if (crc & 1) { crc = (crc >> 1) ^ CRC32_POLYNOMIAL; }
      else { crc >>= 1; }
    }
    crc_table[i] = crc;
  }
}

HASHA_PUBLIC_FUNC uint32_t crc32_oneshot(const uint8_t *data, size_t len)
{
  if (!crc32_table_initialized)
  {
    crc32_init_table(crc32_table);
    crc32_table_initialized = 1;
  }

  uint32_t crc = 0xFFFFFFFF;

  for (size_t i = 0; i < len; i++)
  {
    uint8_t lookup_index = (crc ^ data[i]) & 0xFF;
    crc                  = (crc >> 8) ^ crc32_table[lookup_index];
  }

  return ~crc;
}
