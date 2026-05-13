#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "/src/cjson/cJSON.h"

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a cJSON object to add an object to
  cJSON *parent = cJSON_CreateObject();
  if (parent == NULL) {
    return 0;
  }

  // Ensure the data is null-terminated for string usage
  char *key = (char *)malloc(size + 1);
  if (key == NULL) {
    cJSON_Delete(parent);
    return 0;
  }
  memcpy(key, data, size);
  key[size] = '\0';

  // Call the function-under-test
  cJSON *new_object = cJSON_AddObjectToObject(parent, key);

  // Clean up
  free(key);
  cJSON_Delete(parent);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
