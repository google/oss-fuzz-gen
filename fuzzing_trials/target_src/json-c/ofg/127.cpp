#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
  // Initialize the FuzzedDataProvider with the input data
  FuzzedDataProvider fuzzed_data(data, size);

  // Consume a boolean value to decide if we should create a new JSON object or array
  bool create_object = fuzzed_data.ConsumeBool();

  // Create a JSON object or array based on the consumed boolean
  struct json_object *json_obj = create_object ? json_object_new_object() : json_object_new_array();

  // Consume bytes to create a key-value pair if it's a JSON object
  if (create_object) {
    while (fuzzed_data.remaining_bytes() > 0) {
      std::string key = fuzzed_data.ConsumeRandomLengthString(10);
      std::string value = fuzzed_data.ConsumeRandomLengthString(10);
      json_object_object_add(json_obj, key.c_str(), json_object_new_string(value.c_str()));
    }
  } else {
    // If it's a JSON array, add random strings to the array
    while (fuzzed_data.remaining_bytes() > 0) {
      std::string value = fuzzed_data.ConsumeRandomLengthString(10);
      json_object_array_add(json_obj, json_object_new_string(value.c_str()));
    }
  }

  // Consume an integral value for the second parameter
  int option = fuzzed_data.ConsumeIntegral<int>();

  // Initialize a size_t variable for the third parameter
  size_t length = 0;

  // Call the function-under-test
  const char *result = json_object_to_json_string_length(json_obj, option, &length);

  // Cleanup
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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
