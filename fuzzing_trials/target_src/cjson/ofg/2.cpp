#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
  cJSON *json;
  char *key = NULL;
  size_t key_length = 0;

  // Ensure the input size is sufficient for a JSON object and a key
  if (size < 2) {
    return 0;
  }

  // Parse the input data as a JSON object
  json = cJSON_ParseWithLength((const char *)data, size);
  if (json == NULL) {
    return 0;
  }

  // Find a key within the JSON object
  cJSON *first_item = cJSON_GetArrayItem(json, 0);
  if (first_item != NULL && cJSON_IsString(first_item)) {
    key = first_item->valuestring;
    key_length = strlen(key);
  }

  // If no key is found, create a dummy key
  if (key == NULL) {
    key_length = size > 1 ? size - 1 : 1;
    key = (char *)malloc(key_length + 1);
    if (key == NULL) {
      cJSON_Delete(json);
      return 0;
    }
    memcpy(key, data, key_length);
    key[key_length] = '\0';
  }

  // Call the function-under-test
  cJSON_DeleteItemFromObject(json, key);

  // Clean up
  if (key != NULL && key != first_item->valuestring) {
    free(key);
  }
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
