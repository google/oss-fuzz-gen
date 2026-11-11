#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
  cJSON *root = NULL;
  cJSON *item = NULL;
  cJSON *detached_item = NULL;
  char *json_string = NULL;

  if (size == 0 || data[size - 1] != '\0') {
    return 0;
  }

  json_string = (char *)malloc(size + 1);
  if (json_string == NULL) {
    return 0;
  }
  memcpy(json_string, data, size);
  json_string[size] = '\0';

  root = cJSON_Parse(json_string);
  if (root == NULL) {
    free(json_string);
    return 0;
  }

  item = cJSON_GetArrayItem(root, 0);
  if (item != NULL) {
    detached_item = cJSON_DetachItemViaPointer(root, item);
    if (detached_item != NULL) {
      cJSON_Delete(detached_item);
    }
  }

  cJSON_Delete(root);
  free(json_string);

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
