#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy

#include "ares.h"

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_rr_key_t)) {
    return 0;
  }

  /* Ensure the data is large enough to be cast to ares_dns_rr_key_t */
  ares_dns_rr_key_t key;
  memcpy(&key, data, sizeof(ares_dns_rr_key_t));

  /* Call the function-under-test */
  char *result = ares_dns_rr_key_tostr(key);

  /* Free the result if it is not NULL */
  if (result) {
    free(result);
  }

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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
