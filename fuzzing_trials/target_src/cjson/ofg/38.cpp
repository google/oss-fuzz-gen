#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Ensure the input data is null-terminated for string operations
  char *null_terminated_data = (char *)malloc(size + 1);
  if (null_terminated_data == NULL) {
    return 0;
  }
  memcpy(null_terminated_data, data, size);
  null_terminated_data[size] = '\0';

  // Parse the input data as a JSON object
  cJSON *json = cJSON_Parse(null_terminated_data);
  if (json == NULL || !cJSON_IsObject(json)) {
    free(null_terminated_data);
    return 0;
  }

  // Use a portion of the input data as the key
  size_t key_length = size / 2;
  char *key = (char *)malloc(key_length + 1);
  if (key == NULL) {
    cJSON_Delete(json);
    free(null_terminated_data);
    return 0;
  }
  memcpy(key, data, key_length);
  key[key_length] = '\0';

  // Call the function-under-test
  cJSON *detached_item = cJSON_DetachItemFromObject(json, key);

  // Clean up
  if (detached_item != NULL) {
    cJSON_Delete(detached_item);
  }
  cJSON_Delete(json);
  free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
