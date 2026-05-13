#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Use the first few bytes of data to determine the size for cJSON_malloc
  size_t malloc_size = (size_t)data[0];

  // Call the function-under-test
  void *allocated_memory = cJSON_malloc(malloc_size);

  // Free the allocated memory if it's not NULL
  if (allocated_memory != NULL) {
    free(allocated_memory);
  }

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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
