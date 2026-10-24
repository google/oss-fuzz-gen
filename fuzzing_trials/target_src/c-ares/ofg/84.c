#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <ares_dns.h> // Include this for ares_dns_addr_to_ptr

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
  if (size < sizeof(struct ares_addr)) {
    return 0;
  }

  struct ares_addr addr;
  memcpy(&addr, data, sizeof(struct ares_addr));

  char *result = ares_dns_addr_to_ptr(&addr);
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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
