#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
  /* Ensure the input data is null-terminated for safe string operations */
  char *str = (char *)malloc(size + 1);
  if (!str) {
    return 0;
  }
  memcpy(str, data, size);
  str[size] = '\0';

  ares_dns_class_t qclass;
  
  /* Call the function-under-test */
  ares_dns_class_fromstr(&qclass, str);

  free(str);
  return 0;
}