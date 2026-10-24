#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
  if (size < sizeof(float)) {
    return 0;
  }

  int num_floats = size / sizeof(float);
  float *float_array = (float *)malloc(num_floats * sizeof(float));
  if (float_array == NULL) {
    return 0;
  }

  memcpy(float_array, data, num_floats * sizeof(float));

  cJSON *json_array = cJSON_CreateFloatArray(float_array, num_floats);

  if (json_array != NULL) {
    cJSON_Delete(json_array);
  }

  free(float_array);

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
