#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Ensure the data is null-terminated to be used as a string
  char *input_data = (char *)malloc(size + 1);
  if (!input_data) {
    return 0;
  }
  memcpy(input_data, data, size);
  input_data[size] = '\0';

  // Parse the input data as a cJSON object
  cJSON *json = cJSON_Parse(input_data);
  if (json == NULL) {
    free(input_data);
    return 0;
  }

  // Use a portion of the data as the key for cJSON_GetObjectItemCaseSensitive
  const char *key = input_data;

  // Call the function-under-test
  cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);

  // Clean up
  cJSON_Delete(json);
  free(input_data);

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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
