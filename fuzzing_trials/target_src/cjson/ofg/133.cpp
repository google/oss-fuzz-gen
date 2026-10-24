#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Ensure null-termination of the string
  char *json_string = (char *)malloc(size + 1);
  if (!json_string) {
    return 0;
  }
  memcpy(json_string, data, size);
  json_string[size] = '\0';

  // Parse the JSON data
  cJSON *json = cJSON_Parse(json_string);
  free(json_string);

  if (json == NULL) {
    return 0;
  }

  // Extract a key from the data
  size_t key_length = data[0] % (size - 1) + 1; // Ensure key_length is within bounds
  char *key = (char *)malloc(key_length + 1);
  if (!key) {
    cJSON_Delete(json);
    return 0;
  }
  memcpy(key, data + 1, key_length);
  key[key_length] = '\0';

  // Call the function-under-test
  cJSON *item = cJSON_GetObjectItem(json, key);

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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
