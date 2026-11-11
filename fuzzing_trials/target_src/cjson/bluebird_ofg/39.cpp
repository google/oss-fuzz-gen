#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Split the data into two parts: one for the key, and one for the value.
  size_t key_size = data[0] % size; // Ensure key_size is within bounds.
  size_t value_size = size - key_size - 1; // Ensure there's at least 1 byte for value.

  // Allocate memory for key and value
  char *key = (char *)malloc(key_size + 1);
  char *value = (char *)malloc(value_size + 1);

  if (!key || !value) {
    free(key);
    free(value);
    return 0;
  }

  // Copy data to key and value, ensuring null-termination
  memcpy(key, data + 1, key_size);
  key[key_size] = '\0';
  memcpy(value, data + 1 + key_size, value_size);
  value[value_size] = '\0';

  // Create a cJSON object and item
  cJSON *object = cJSON_CreateObject();
  cJSON *item = cJSON_CreateString(value);

  if (object && item) {
    // Call the function-under-test
    cJSON_ReplaceItemInObjectCaseSensitive(object, key, item);
  }

  // Clean up
  cJSON_Delete(object);
  cJSON_Delete(item);
  free(key);
  free(value);

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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
