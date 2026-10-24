#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
  // Ensure the data is null-terminated for string operations
  if (size == 0 || data[size - 1] != '\0') {
    return 0;
  }

  // Create a cJSON object
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    return 0;
  }

  // Create a string to set as the value
  const char *value_string = (const char *)data;

  // Call the function-under-test
  char *result = cJSON_SetValuestring(json, value_string);

  // Clean up
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

    LLVMFuzzerTestOneInput_153(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
