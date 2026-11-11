#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
  if (size < 3) return 0; // Ensure there's enough data to create cJSON items

  // Create dummy cJSON items
  cJSON *parent = cJSON_CreateObject();
  cJSON *item_to_replace = cJSON_CreateObject();
  cJSON *replacement_item = cJSON_CreateObject();

  // Ensure the items are not NULL
  if (parent == NULL || item_to_replace == NULL || replacement_item == NULL) {
    cJSON_Delete(parent);
    cJSON_Delete(item_to_replace);
    cJSON_Delete(replacement_item);
    return 0;
  }

  // Add the item to replace to the parent
  cJSON_AddItemToObject(parent, "item", item_to_replace);

  // Call the function-under-test
  cJSON_ReplaceItemViaPointer(parent, item_to_replace, replacement_item);

  // Clean up
  cJSON_Delete(parent); // This will also delete item_to_replace and replacement_item

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

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
