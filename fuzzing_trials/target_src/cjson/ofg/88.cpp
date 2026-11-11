#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Ensure null-termination for the JSON string
  char *json_data = (char *)malloc(size + 1);
  if (json_data == NULL) {
    return 0;
  }
  memcpy(json_data, data, size);
  json_data[size] = '\0';

  // Parse the JSON data
  cJSON *json = cJSON_Parse(json_data);
  free(json_data);

  if (json == NULL) {
    return 0;
  }

  // Use the first byte as the length of the key
  size_t key_length = data[0] % (size - 1) + 1; // Ensure key_length is at least 1
  if (key_length >= size) {
    cJSON_Delete(json);
    return 0;
  }

  // Extract the key from the input data
  char *key = (char *)malloc(key_length + 1);
  if (key == NULL) {
    cJSON_Delete(json);
    return 0;
  }
  memcpy(key, data + 1, key_length);
  key[key_length] = '\0';

  // Call the function-under-test
  cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);

  // Clean up
  free(key);
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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
