#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
  cJSON *json;
  cJSON *array_item;
  int index;

  // Ensure the input data is null-terminated
  if (size == 0 || data[size - 1] != '\0') {
    return 0;
  }

  // Parse the input data as JSON
  json = cJSON_Parse((const char *)data);
  if (json == NULL) {
    return 0;
  }

  // Check if the parsed JSON is an array
  if (!cJSON_IsArray(json)) {
    cJSON_Delete(json);
    return 0;
  }

  // Use a simple index for fuzzing, e.g., 0, 1, -1, etc.
  index = (int)(data[0] % 5) - 2; // index will be -2, -1, 0, 1, or 2

  // Call the function-under-test
  array_item = cJSON_GetArrayItem(json, index);

  // Clean up
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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
