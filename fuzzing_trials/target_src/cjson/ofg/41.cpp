#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
  if (size < sizeof(int) + 1) {
    return 0;
  }

  // Determine the number of strings
  int num_strings = *((int *)data);
  data += sizeof(int);
  size -= sizeof(int);

  // Allocate memory for the array of strings
  const char **string_array = (const char **)malloc(num_strings * sizeof(char *));
  if (string_array == NULL) {
    return 0;
  }

  // Populate the string array
  for (int i = 0; i < num_strings; i++) {
    if (size == 0) {
      string_array[i] = "";
    } else {
      size_t str_len = strnlen((const char *)data, size);
      string_array[i] = strndup((const char *)data, str_len);
      if (string_array[i] == NULL) {
        for (int j = 0; j < i; j++) {
          free((void *)string_array[j]);
        }
        free(string_array);
        return 0;
      }
      data += str_len + 1;
      size -= (str_len + 1);
    }
  }

  // Call the function-under-test
  cJSON *json_array = cJSON_CreateStringArray(string_array, num_strings);

  // Clean up
  for (int i = 0; i < num_strings; i++) {
    free((void *)string_array[i]);
  }
  free(string_array);

  if (json_array != NULL) {
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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
