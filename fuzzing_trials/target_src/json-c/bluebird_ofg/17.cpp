#include <sys/stat.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/json_object.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
  if (size < 1) return 0;

  FuzzedDataProvider fuzzed_data(data, size);

  // Create a json_object array
  size_t array_size = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 10);
  struct json_object *json_array = json_object_new_array();
  for (size_t i = 0; i < array_size; ++i) {
    int value = fuzzed_data.ConsumeIntegral<int>();
    struct json_object *jint = json_object_new_int(value);
    json_object_array_add(json_array, jint);
  }

  // Create a json_object key to search for
  int search_key_value = fuzzed_data.ConsumeIntegral<int>();
  struct json_object *search_key = json_object_new_int(search_key_value);

  // Define a comparison function
  int (*compare_func)(const void *, const void *) = [](const void *a, const void *b) {
    struct json_object *ja = *(struct json_object **)a;
    struct json_object *jb = *(struct json_object **)b;
    return json_object_get_int(ja) - json_object_get_int(jb);
  };

  // Call the function under test
  struct json_object *result = json_object_array_bsearch(search_key, json_array, compare_func);

  // Cleanup
  json_object_put(json_array);
  json_object_put(search_key);

  return 0;
}
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
