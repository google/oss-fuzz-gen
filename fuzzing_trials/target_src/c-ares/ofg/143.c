#include <stdint.h>
#include <stddef.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
  /* Ensure that the size of the input data is sufficient to create a valid ares_dns_rr_key_t structure */
  if (size < sizeof(ares_dns_rr_key_t)) {
    return 0;
  }

  /* Cast the input data to a ares_dns_rr_key_t type */
  ares_dns_rr_key_t key;
  key = *(ares_dns_rr_key_t *)data;

  /* Call the function-under-test */
  ares_dns_rec_type_t rec_type = ares_dns_rr_key_to_rec_type(key);

  /* Return 0 to indicate successful execution */
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

    LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
