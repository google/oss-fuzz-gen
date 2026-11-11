#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Split the input data into two parts for key and raw value
  size_t key_len = data[0] % size; // Ensure key_len is within bounds
  size_t raw_len = size - key_len - 1; // Remaining bytes for raw value

  // Allocate memory for key and raw value
  char *key = (char *)malloc(key_len + 1);
  char *raw_value = (char *)malloc(raw_len + 1);

  if (!key || !raw_value) {
    free(key);
    free(raw_value);
    return 0;
  }

  // Copy data into key and raw value
  memcpy(key, data + 1, key_len);
  key[key_len] = '\0'; // Null-terminate the key string

  memcpy(raw_value, data + 1 + key_len, raw_len);
  raw_value[raw_len] = '\0'; // Null-terminate the raw value string

  // Create a cJSON object
  cJSON *json = cJSON_CreateObject();
  if (!json) {
    free(key);
    free(raw_value);
    return 0;
  }

  // Call the function-under-test
  cJSON *result = cJSON_AddRawToObject(json, key, raw_value);

  // Clean up
  cJSON_Delete(json);
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
