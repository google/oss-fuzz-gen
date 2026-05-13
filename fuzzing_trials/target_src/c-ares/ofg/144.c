#include <stddef.h>
#include <stdint.h>
#include <string.h> // Include for memcpy
#include "ares.h"

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_rr_key_t)) {
    return 0;
  }

  ares_dns_rr_key_t key;
  /* Copy data into key, ensuring it doesn't exceed the size of ares_dns_rr_key_t */
  memcpy(&key, data, sizeof(ares_dns_rr_key_t));

  /* Call the function-under-test */
  ares_dns_rec_type_t rec_type = ares_dns_rr_key_to_rec_type(key);

  /* Use rec_type in some way to avoid compiler optimizations removing the call */
  (void)rec_type;

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

    LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
