#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a root cJSON object
  cJSON *root = cJSON_CreateObject();
  if (root == NULL) {
    return 0;
  }

  // Create a child cJSON object
  cJSON *child = cJSON_CreateObject();
  if (child == NULL) {
    cJSON_Delete(root);
    return 0;
  }

  // Ensure the string is null-terminated and non-empty
  char *key = (char *)malloc(size + 1);
  if (key == NULL) {
    cJSON_Delete(root);
    cJSON_Delete(child);
    return 0;
  }
  memcpy(key, data, size);
  key[size] = '\0';

  // Call the function-under-test
  cJSON_bool result = cJSON_AddItemReferenceToObject(root, key, child);

  // Clean up
  free(key);
  cJSON_Delete(root); // This will also delete the child

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

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
