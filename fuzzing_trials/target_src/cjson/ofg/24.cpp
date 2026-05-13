#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "/src/cjson/cJSON.h"

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
  // Ensure the input data is null-terminated
  if (size == 0) {
    return 0;
  }

  // Allocate memory for null-terminated data
  uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
  if (!null_terminated_data) {
    return 0;
  }

  // Copy data and null-terminate it
  memcpy(null_terminated_data, data, size);
  null_terminated_data[size] = '\0';

  // Parse the input data as a cJSON object
  cJSON *json = cJSON_Parse((const char *)null_terminated_data);
  free(null_terminated_data);
  if (json == NULL) {
    return 0;
  }

  // Call the function-under-test
  cJSON_bool result = cJSON_IsString(json);

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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
