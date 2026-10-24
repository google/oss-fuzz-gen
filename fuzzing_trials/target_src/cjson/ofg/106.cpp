#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "/src/cjson/cJSON.h"

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
  // Create a buffer to ensure the data is null-terminated
  char *buffer = (char *)malloc(size + 1);
  if (buffer == NULL) {
    return 0;
  }

  // Copy the data and null-terminate it
  memcpy(buffer, data, size);
  buffer[size] = '\0';

  // Create a cJSON object using cJSON_CreateRaw
  cJSON *json = cJSON_CreateRaw(buffer);

  // If the JSON object is created successfully, delete it
  if (json != NULL) {
    cJSON_Delete(json);
  }

  // Free the buffer
  free(buffer);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
