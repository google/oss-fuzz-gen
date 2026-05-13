#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
  if (size < 3) {
    return 0;
  }

  // Split the input data into three parts for the function parameters
  size_t part1_size = size / 3;
  size_t part2_size = (size - part1_size) / 2;
  size_t part3_size = size - part1_size - part2_size;

  // Ensure null-termination for string parameters
  char *key = (char *)malloc(part2_size + 1);
  char *value = (char *)malloc(part3_size + 1);

  if (key == NULL || value == NULL) {
    free(key);
    free(value);
    return 0;
  }

  memcpy(key, data + part1_size, part2_size);
  key[part2_size] = '\0';

  memcpy(value, data + part1_size + part2_size, part3_size);
  value[part3_size] = '\0';

  // Create a new cJSON object
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    free(key);
    free(value);
    return 0;
  }

  // Call the function under test
  cJSON *result = cJSON_AddStringToObject(json, key, value);

  // Clean up
  cJSON_Delete(json);
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

    LLVMFuzzerTestOneInput_137(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
