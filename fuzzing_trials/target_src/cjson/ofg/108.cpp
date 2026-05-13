#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
  void *memory;

  // Ensure that size is non-zero to allocate memory
  if (size == 0) {
    return 0;
  }

  // Allocate memory and copy the input data into it
  memory = malloc(size);
  if (memory == NULL) {
    return 0;
  }
  memcpy(memory, data, size);

  // Call the function-under-test
  cJSON_free(memory);

  return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
