#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
  if (size < 3) {
    return 0;
  }

  // Split the input data into two parts for key and raw value
  size_t key_size = size / 2;
  size_t raw_size = size - key_size;

  // Ensure null-termination for the key and raw value strings
  char *key = (char *)malloc(key_size + 1);
  char *raw_value = (char *)malloc(raw_size + 1);

  if (key == NULL || raw_value == NULL) {
    free(key);
    free(raw_value);
    return 0;
  }

  memcpy(key, data, key_size);
  key[key_size] = '\0';

  memcpy(raw_value, data + key_size, raw_size);
  raw_value[raw_size] = '\0';

  // Create a cJSON object
  cJSON *json_object = cJSON_CreateObject();
  if (json_object == NULL) {
    free(key);
    free(raw_value);
    return 0;
  }

  // Call the function-under-test
  cJSON *result = cJSON_AddRawToObject(json_object, key, raw_value);

  // Clean up
  cJSON_Delete(json_object);
  free(key);
  free(raw_value);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
