#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Parse the input data as a JSON object
  cJSON *json = cJSON_ParseWithLength((const char *)data, size);
  if (json == NULL) {
    return 0;
  }

  // Allocate a buffer for the preallocated print
  int buffer_size = size * 2;
  char *buffer = (char *)malloc(buffer_size);
  if (buffer == NULL) {
    cJSON_Delete(json);
    return 0;
  }

  // Use the first byte of data to determine if the print should be formatted
  cJSON_bool format = (data[0] % 2 == 0) ? true : false;

  // Call the function-under-test
  cJSON_bool result = cJSON_PrintPreallocated(json, buffer, buffer_size, format);

  // Clean up
  free(buffer);
  cJSON_Delete(json);

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
