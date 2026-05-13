#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
  /* Ensure the input data is null-terminated to safely use as a string */
  char *null_terminated_str = (char *)malloc(size + 1);
  if (!null_terminated_str) {
    return 0; /* Exit if memory allocation fails */
  }
  memcpy(null_terminated_str, data, size);
  null_terminated_str[size] = '\0';

  ares_dns_rec_type_t qtype;
  
  /* Call the function-under-test */
  ares_dns_rec_type_fromstr(&qtype, null_terminated_str);

  /* Free the allocated memory */
  free(null_terminated_str);

  return 0;
}