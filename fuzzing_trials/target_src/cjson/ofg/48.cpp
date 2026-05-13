#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
  cJSON *json;
  char *printed_json = NULL;
  int prebuffer;
  cJSON_bool format;

  // Check if the input size is sufficient
  if (size < 2) return 0;

  // Parse the input data into a cJSON object
  json = cJSON_ParseWithLength((const char *)data, size);

  if (json == NULL) {
    return 0;
  }

  // Extract prebuffer and format from the input data
  prebuffer = (int)data[0];
  format = (cJSON_bool)(data[1] % 2);

  // Call the function-under-test
  printed_json = cJSON_PrintBuffered(json, prebuffer, format);

  // Free allocated memory
  if (printed_json != NULL) {
    free(printed_json);
  }

  // Delete the cJSON object
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
