#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>  // For memcpy
#include "ares.h"    // Ensure this header provides necessary type and function declarations

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
  /* Ensure we have enough data to extract necessary parameters */
  if (size < sizeof(ares_dns_rr_key_t) + sizeof(unsigned short)) {
    return 0;
  }

  /* Extract ares_dns_rr_key_t from the data */
  ares_dns_rr_key_t key;
  memcpy(&key, data, sizeof(ares_dns_rr_key_t));

  /* Extract unsigned short opt from the data */
  unsigned short opt;
  memcpy(&opt, data + sizeof(ares_dns_rr_key_t), sizeof(unsigned short));

  /* Call the function-under-test */
  ares_dns_opt_datatype_t result = ares_dns_opt_get_datatype(key, opt);

  /* Use the result in some way to avoid compiler optimizations */
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
