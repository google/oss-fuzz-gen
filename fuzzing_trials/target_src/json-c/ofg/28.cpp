#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fuzzed_data(data, size);

  // Consume a portion of the input data to create a JSON object string
  std::string json_string = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes() / 2);

  // Parse the JSON string to create a json_object
  struct json_object *json_obj = json_tokener_parse(json_string.c_str());
  if (json_obj == NULL) {
    return 0; // If parsing fails, exit early
  }

  // Define a simple comparison function
  auto compare_func = [](const void *a, const void *b) -> int {
    // For fuzzing purposes, we can use a simple comparison that always returns 0
    return 0;
  };

  // Call the function under test
  json_object_array_sort(json_obj, compare_func);

  // Clean up
  json_object_put(json_obj);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
