#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
  if (size < sizeof(double)) {
    return 0;
  }

  int array_size = size / sizeof(double);
  double *double_array = (double *)malloc(array_size * sizeof(double));

  if (double_array == NULL) {
    return 0;
  }

  memcpy(double_array, data, array_size * sizeof(double));

  cJSON *json_array = cJSON_CreateDoubleArray(double_array, array_size);

  if (json_array != NULL) {
    cJSON_Delete(json_array);
  }

  free(double_array);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
