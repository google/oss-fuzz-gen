#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Ensure the data is null-terminated for string operations
  char *key = (char *)malloc(size + 1);
  if (key == NULL) {
    return 0;
  }
  memcpy(key, data + 1, size - 1);
  key[size - 1] = '\0';

  // Create a simple cJSON object
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    free(key);
    return 0;
  }

  // Add a sample item to the object
  cJSON_AddStringToObject(json, "sample_key", "sample_value");

  // Call the function-under-test
  cJSON_DeleteItemFromObjectCaseSensitive(json, key);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
