#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  // Ensure the input data is null-terminated
  char *input = (char *)malloc(size + 1);
  if (input == NULL) {
    return 0;
  }
  memcpy(input, data, size);
  input[size] = '\0';

  // Use a pointer to track parsing end
  const char *end = NULL;

  // Randomly decide whether to require a null-terminated string
  cJSON_bool require_null_terminated = (data[0] % 2 == 0) ? cJSON_True : cJSON_False;

  // Call the function-under-test
  cJSON *json = cJSON_ParseWithOpts(input, &end, require_null_terminated);

  // Clean up
  if (json != NULL) {
    cJSON_Delete(json);
  }
  free(input);

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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
