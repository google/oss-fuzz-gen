#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
  cJSON *json = NULL;
  cJSON *detached_item = NULL;
  int index = 0;

  // Ensure the input data is null-terminated for cJSON parsing
  if (size == 0 || data[size - 1] != '\0') {
    return 0;
  }

  // Parse the input data as a JSON array
  json = cJSON_Parse((const char *)data);
  if (json == NULL || !cJSON_IsArray(json)) {
    cJSON_Delete(json);
    return 0;
  }

  // Set the index to a valid position within the array
  index = size % cJSON_GetArraySize(json);

  // Detach an item from the JSON array
  detached_item = cJSON_DetachItemFromArray(json, index);

  // Clean up
  cJSON_Delete(json);
  cJSON_Delete(detached_item);

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
