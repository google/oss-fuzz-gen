#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_169(const unsigned char *data, size_t size) {
  /* Initialize the output parameter */
  struct ares_caa_reply *caa_out = NULL;

  /* Call the function-under-test */
  ares_parse_caa_reply(data, (int)size, &caa_out);

  /* Free the allocated resources if any */
  if (caa_out) {
    ares_free_data(caa_out);
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

    LLVMFuzzerTestOneInput_169(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
