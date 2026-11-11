#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Create a root array
  cJSON *array = cJSON_CreateArray();
  if (array == NULL) {
    return 0;
  }

  // Create a new item to insert
  cJSON *item = cJSON_CreateString("fuzz_item");
  if (item == NULL) {
    cJSON_Delete(array);
    return 0;
  }

  // Use the first byte of data to determine the index
  int index = data[0] % (size + 1);  // Ensure index is within bounds

  // Insert the item into the array
  cJSON_InsertItemInArray(array, index, item);

  // Clean up
  cJSON_Delete(array);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
