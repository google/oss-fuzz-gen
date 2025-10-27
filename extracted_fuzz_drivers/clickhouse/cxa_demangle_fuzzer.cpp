#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern "C" char *__cxa_demangle(const char *mangled_name, char *buf, size_t *n, int *status);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *str = new char[size + 1];
  memcpy(str, data, size);
  str[size] = 0;
  free(__cxa_demangle(str, 0, 0, 0));
  delete[] str;
  return 0;
}
