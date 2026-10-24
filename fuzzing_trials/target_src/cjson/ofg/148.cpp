#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
  cJSON *json;

  // Ensure the data is null-terminated for parsing
  char *input = (char *)malloc(size + 1);
  if (input == NULL) {
    return 0;
  }
  memcpy(input, data, size);
  input[size] = '\0';

  // Parse the input data as JSON
  json = cJSON_Parse(input);

  // Retrieve the error pointer
  const char *error_ptr = cJSON_GetErrorPtr();

  // Free the allocated memory
  free(input);

  // Delete the cJSON object if it was successfully created
  if (json != NULL) {
    cJSON_Delete(json);
  }

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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
