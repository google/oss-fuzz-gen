#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
  cJSON *json;
  int index;

  // Ensure we have enough data to proceed
  if (size < 5) return 0;

  // Parse the input data as JSON
  json = cJSON_ParseWithLength((const char *)data, size - 1);

  // If parsing fails, exit early
  if (json == NULL) return 0;

  // Use the first byte of data to determine the index
  index = data[size - 1] % cJSON_GetArraySize(json);

  // Call the function-under-test
  cJSON_DeleteItemFromArray(json, index);

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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
