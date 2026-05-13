#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
  // The function cJSON_CreateNull does not take any input parameters,
  // so we do not need to use the `data` and `size` parameters.
  (void)data;
  (void)size;

  // Call the function-under-test
  cJSON *json_null = cJSON_CreateNull();

  // Clean up the created cJSON object
  if (json_null != NULL) {
    cJSON_Delete(json_null);
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
