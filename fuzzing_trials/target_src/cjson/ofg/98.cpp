#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
  if (size < 2) return 0; // Ensure there is enough data to process

  // Split the input data into two parts for creating two cJSON objects
  size_t mid = size / 2;

  // Create a cJSON object for the array
  cJSON *array = cJSON_CreateArray();
  if (array == NULL) return 0;

  // Create a cJSON object from the first half of the data
  cJSON *item = cJSON_ParseWithLength((const char *)data, mid);
  if (item == NULL) {
    cJSON_Delete(array);
    return 0;
  }

  // Attempt to add the item to the array
  cJSON_bool result = cJSON_AddItemToArray(array, item);

  // Clean up
  cJSON_Delete(array); // This will also delete 'item' if it was successfully added

  return result;
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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
