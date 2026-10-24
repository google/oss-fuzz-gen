#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include string.h for memcpy
#include "ares.h"   // Ensure this includes declarations for ares_dns_rr_key_t, ares_dns_datatype_t, and ares_dns_rr_key_datatype

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
  /* Ensure the data is large enough to fill the ares_dns_rr_key_t structure */
  if (size < sizeof(ares_dns_rr_key_t)) {
    return 0;
  }

  /* Initialize the key from the input data */
  ares_dns_rr_key_t key;
  memcpy(&key, data, sizeof(ares_dns_rr_key_t));

  /* Call the function-under-test */
  ares_dns_datatype_t result = ares_dns_rr_key_datatype(key);

  /* Use the result in some way to avoid compiler optimizations removing the call */
  (void)result;

  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
