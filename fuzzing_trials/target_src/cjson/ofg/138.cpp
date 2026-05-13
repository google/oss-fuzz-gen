#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
  if (size < 3) {
    return 0;
  }

  // Split the input data into three parts
  size_t key_len = data[0] % (size - 2) + 1;
  size_t value_len = data[1] % (size - key_len - 1) + 1;
  size_t json_data_len = size - key_len - value_len - 2;

  char *key = (char *)malloc(key_len + 1);
  char *value = (char *)malloc(value_len + 1);
  char *json_data = (char *)malloc(json_data_len + 1);

  if (!key || !value || !json_data) {
    free(key);
    free(value);
    free(json_data);
    return 0;
  }

  memcpy(key, data + 2, key_len);
  key[key_len] = '\0';

  memcpy(value, data + 2 + key_len, value_len);
  value[value_len] = '\0';

  memcpy(json_data, data + 2 + key_len + value_len, json_data_len);
  json_data[json_data_len] = '\0';

  // Parse the initial JSON data
  cJSON *json = cJSON_Parse(json_data);
  if (json == NULL) {
    free(key);
    free(value);
    free(json_data);
    return 0;
  }

  // Call the function-under-test
  cJSON *result = cJSON_AddStringToObject(json, key, value);

  // Clean up
  cJSON_Delete(json);
  free(key);
  free(value);
  free(json_data);

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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
