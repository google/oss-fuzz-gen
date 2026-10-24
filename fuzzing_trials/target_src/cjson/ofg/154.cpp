#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a cJSON object
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    return 0;
  }

  // Ensure the string is null-terminated
  char *value_string = (char *)malloc(size + 1);
  if (value_string == NULL) {
    cJSON_Delete(json);
    return 0;
  }
  memcpy(value_string, data, size);
  value_string[size] = '\0';

  // Call the function under test
  char *result = cJSON_SetValuestring(json, value_string);

  // Clean up
  free(value_string);
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

    LLVMFuzzerTestOneInput_154(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
