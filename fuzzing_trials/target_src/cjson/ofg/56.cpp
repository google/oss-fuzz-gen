#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
  char *json_string;

  // Ensure the input data is null-terminated
  if (size == 0 || data[size - 1] != '\0') {
    return 0;
  }

  // Allocate memory for the JSON string and copy the data
  json_string = (char *)malloc(size + 1);
  if (json_string == NULL) {
    return 0;
  }
  memcpy(json_string, data, size);
  json_string[size] = '\0';

  // Call the function-under-test
  cJSON_Minify(json_string);

  // Free the allocated memory
  free(json_string);

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
