#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
  /* Ensure there's enough data to extract a valid ares_dns_section_t value */
  if (size < sizeof(ares_dns_section_t)) {
    return 0;
  }

  /* Extract ares_dns_section_t value from the input data */
  ares_dns_section_t section = *(ares_dns_section_t *)data;

  /* Call the function-under-test */
  char *result = ares_dns_section_tostr(section);

  /* Since the function returns a string, we should ensure it's not NULL */
  if (result != NULL) {
    printf("Result: %s\n", result);
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
