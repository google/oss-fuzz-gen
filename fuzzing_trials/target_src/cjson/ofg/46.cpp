#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
  cJSON *json;
  char *unformatted_json = NULL;

  // Ensure the input data is null-terminated
  if (size == 0 || data[size - 1] != '\0') {
    return 0;
  }

  // Parse the input data into a cJSON object
  json = cJSON_Parse((const char *)data);
  if (json == NULL) {
    return 0;
  }

  // Print the JSON object as an unformatted string
  unformatted_json = cJSON_PrintUnformatted(json);
  if (unformatted_json != NULL) {
    // Free the unformatted JSON string
    free(unformatted_json);
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
