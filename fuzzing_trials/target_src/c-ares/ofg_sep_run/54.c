#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // Extract parts of the input data for parameters
  size_t name_len = size / 2;
  char *name = (char *)malloc(name_len + 1);
  if (!name) {
    return 0;
  }
  memcpy(name, data, name_len);
  name[name_len] = '\0';

  int dnsclass = (int)data[name_len] % 256;
  int type = (int)data[name_len + 1] % 256;
  unsigned short id = (unsigned short)data[name_len + 2] % 65536;
  int rd = (int)data[name_len + 3] % 2;

  unsigned char *buf = NULL;
  int buflen = 0;

  // Call the function-under-test
  ares_mkquery(name, dnsclass, type, id, rd, &buf, &buflen);

  // Clean up
  free(name);
  if (buf) {
    free(buf);
  }

  return 0;
}