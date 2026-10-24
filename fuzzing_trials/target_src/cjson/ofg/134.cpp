#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Ensure null-termination for the key string
  char *key = (char *)malloc(size);
  if (key == NULL) {
    return 0;
  }
  memcpy(key, data, size - 1);
  key[size - 1] = '\0';

  // Parse the input data as JSON
  cJSON *json = cJSON_Parse((const char *)data);
  if (json == NULL) {
    free(key);
    return 0;
  }

  // Call the function-under-test
  cJSON *item = cJSON_GetObjectItem(json, key);

  // Clean up
  cJSON_Delete(json);
  free(key);

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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
