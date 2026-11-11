#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // Include this for malloc and free
#include "ares.h"

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  /* Ensure the input data is null-terminated to be used as a string */
  char *str = (char *)malloc(size + 1);
  if (!str) {
    return 0;
  }
  memcpy(str, data, size);
  str[size] = '\0';

  ares_dns_rec_type_t qtype;
  ares_bool_t result = ares_dns_rec_type_fromstr(&qtype, str);

  /* Free the allocated memory */
  free(str);

  return 0;
}