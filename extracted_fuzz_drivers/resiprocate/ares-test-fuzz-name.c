/* Code ported from c-ares test/ares-test-fuzz-name.c */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"
#include "ares_nameser.h"

// Entrypoint for Clang's libfuzzer, exercising query creation.
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
  // Null terminate the data.
  char *name = malloc(size + 1);
  name[size] = '\0';
  memcpy(name, data, size);

  unsigned char *buf = NULL;
  int buflen = 0;
  ares_mkquery(name, ns_c_in, ns_t_aaaa, 1234, 0, &buf, &buflen);
  free(buf);
  free(name);
  return 0;
}
