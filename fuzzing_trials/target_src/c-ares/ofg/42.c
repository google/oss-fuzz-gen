#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_rr_key_t) + sizeof(unsigned short)) {
    return 0;
  }

  /* Extract ares_dns_rr_key_t from the input data */
  ares_dns_rr_key_t key;
  memcpy(&key, data, sizeof(ares_dns_rr_key_t));
  data += sizeof(ares_dns_rr_key_t);
  size -= sizeof(ares_dns_rr_key_t);

  /* Extract unsigned short opt from the input data */
  unsigned short opt;
  memcpy(&opt, data, sizeof(unsigned short));

  /* Call the function-under-test */
  char *result = ares_dns_opt_get_name(key, opt);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
