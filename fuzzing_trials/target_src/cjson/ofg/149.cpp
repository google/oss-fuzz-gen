#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
  // Call the function-under-test
  cJSON *json_object = cJSON_CreateObject();

  // Check if the object creation was successful
  if (json_object != NULL) {
    // Optionally, you can add some operations on the created object here
    // For example, adding a string or number to the JSON object
    if (size > 0) {
      char key[] = "key";
      char value[] = "value";
      cJSON_AddStringToObject(json_object, key, value);
    }

    // Finally, delete the created JSON object to avoid memory leaks
    cJSON_Delete(json_object);
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

    LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
