#include "uri/uri.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = calloc(size + 1, sizeof(char));
  if (!buf)
    return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';
  struct uri uri;
  uri_create(&uri, buf);
  uri_destroy(&uri);
  free(buf);

  return 0;
}
