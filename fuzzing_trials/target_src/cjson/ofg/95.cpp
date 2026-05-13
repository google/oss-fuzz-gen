#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
  const char *end_ptr = NULL;
  cJSON_bool require_null_termination = cJSON_False;
  cJSON *json = NULL;

  if (size == 0) {
    return 0;
  }

  // Ensure the data is null-terminated
  char *input_data = (char *)malloc(size + 1);
  if (input_data == NULL) {
    return 0;
  }
  memcpy(input_data, data, size);
  input_data[size] = '\0';

  // Try both options for require_null_termination
  require_null_termination = cJSON_False;
  json = cJSON_ParseWithLengthOpts(input_data, size, &end_ptr, require_null_termination);
  if (json != NULL) {
    cJSON_Delete(json);
  }

  require_null_termination = cJSON_True;
  json = cJSON_ParseWithLengthOpts(input_data, size, &end_ptr, require_null_termination);
  if (json != NULL) {
    cJSON_Delete(json);
  }

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
