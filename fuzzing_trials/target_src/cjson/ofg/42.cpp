#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Determine the number of strings
  int num_strings = data[0] % 10 + 1; // Limit to a reasonable number of strings
  const char **string_array = (const char **)malloc(num_strings * sizeof(char *));
  if (string_array == NULL) {
    return 0;
  }

  size_t offset = 1;
  for (int i = 0; i < num_strings; ++i) {
    if (offset >= size) {
      string_array[i] = "";
    } else {
      size_t str_len = data[offset] % (size - offset);
      char *str = (char *)malloc(str_len + 1);
      if (str == NULL) {
        string_array[i] = "";
      } else {
        memcpy(str, data + offset, str_len);
        str[str_len] = '\0';
        string_array[i] = str;
        offset += str_len + 1;
      }
    }
  }

  cJSON *json_array = cJSON_CreateStringArray(string_array, num_strings);

  // Clean up
  for (int i = 0; i < num_strings; ++i) {
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
