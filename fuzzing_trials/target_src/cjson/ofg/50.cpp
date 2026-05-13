#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
  if (size < 2) return 0;

  // Allocate memory for the key and ensure it's null-terminated
  char *key = (char *)malloc(size + 1);
  if (!key) return 0;
  memcpy(key, data, size);
  key[size] = '\0';

  // Create cJSON objects
  cJSON *object = cJSON_CreateObject();
  cJSON *item = cJSON_CreateString("test_value");

  if (object && item) {
    // Add item to object with the fuzzed key
    cJSON_AddItemToObjectCS(object, key, item);

    // Clean up
    cJSON_Delete(object);
  } else {
    if (object) cJSON_Delete(object);
    if (item) cJSON_Delete(item);
  }

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
