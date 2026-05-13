#include <stdint.h>
#include <stdlib.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
  // Create a cJSON array
  cJSON *json_array = cJSON_CreateArray();
  
  // Ensure the array was created successfully
  if (json_array != NULL) {
    // Assume data is a JSON string, parse it
    cJSON *parsed_json = cJSON_ParseWithLength((const char *)data, size);
    if (parsed_json != NULL) {
      // Perform operations on the parsed JSON if needed
      cJSON_Delete(parsed_json);
    }
    // Delete the array to test the creation and deletion process
    cJSON_Delete(json_array);
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
