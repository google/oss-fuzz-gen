#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
  /* Ensure that the size is sufficient to extract a valid ares_dns_rec_type_t */
  if (size < sizeof(ares_dns_rec_type_t)) {
    return 0;
  }

  /* Extract ares_dns_rec_type_t from the input data */
  ares_dns_rec_type_t type = *(ares_dns_rec_type_t *)data;

  /* Initialize count variable */
  size_t count = 0;

  /* Call the function under test */
  ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(type, &count);

  /* Free the allocated memory if any */
  if (keys) {
    free(keys);
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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
