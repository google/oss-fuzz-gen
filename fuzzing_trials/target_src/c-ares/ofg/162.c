#include <stddef.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_162(const unsigned char *data, size_t size) {
  /* Initialize variables */
  unsigned int flags = 0;  /* Set flags to 0 for simplicity */
  ares_dns_record_t *dnsrec = NULL;

  /* Call the function-under-test */
  ares_dns_parse(data, size, flags, &dnsrec);

  /* Free the allocated dnsrec if not NULL */
  if (dnsrec) {
    ares_free_data(dnsrec);
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

    LLVMFuzzerTestOneInput_162(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
