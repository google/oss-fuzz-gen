#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
  // Ensure the data is null-terminated
  char *input_string;
  cJSON *json_string_ref;

  if (size == 0) {
    return 0;
  }

  // Allocate memory for the input string and ensure it is null-terminated
  input_string = (char *)malloc(size + 1);
  if (input_string == NULL) {
    return 0;
  }
  memcpy(input_string, data, size);
  input_string[size] = '\0';

  // Call the function-under-test
  json_string_ref = cJSON_CreateStringReference(input_string);

  // Clean up
  if (json_string_ref != NULL) {
    cJSON_Delete(json_string_ref);
  }
  free(input_string);

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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
