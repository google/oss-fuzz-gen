#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_opcode_t)) {
    return 0;
  }

  /* Extract an ares_dns_opcode_t value from the input data */
  ares_dns_opcode_t opcode = *(const ares_dns_opcode_t *)data;

  /* Call the function-under-test */
  char *result = ares_dns_opcode_tostr(opcode);

  /* Print the result to ensure it is being processed */
  if (result != NULL) {
    printf("Opcode string: %s\n", result);
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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
