#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_rec_type_t)) {
    return 0;
  }

  /* Extract ares_dns_rec_type_t from the input data */
  ares_dns_rec_type_t type;
  memcpy(&type, data, sizeof(ares_dns_rec_type_t));

  /* Call the function-under-test */
  char *result = ares_dns_rec_type_tostr(type);

  /* Normally, you'd do something with the result here, but since it's a string
     representation, we'll just ensure it was called. */
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
