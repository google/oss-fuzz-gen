#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
  // Initialize the FuzzedDataProvider with the input data
  FuzzedDataProvider fuzzed_data(data, size);

  // Create a json_tokener object
  struct json_tokener *tokener = json_tokener_new();

  // Ensure the tokener is not NULL before using it
  if (tokener != nullptr) {
    // Use the fuzzed data to create a string input for json_tokener_parse
    std::string json_input = fuzzed_data.ConsumeRandomLengthString(size);

    // Call the function-under-test
    json_object *parsed_json = json_tokener_parse_ex(tokener, json_input.c_str(), json_input.length());

    // Free the parsed json object if it's not NULL
    if (parsed_json != nullptr) {
      json_object_put(parsed_json);
    }

    // Free the json_tokener object
    json_tokener_free(tokener);
  }

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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
