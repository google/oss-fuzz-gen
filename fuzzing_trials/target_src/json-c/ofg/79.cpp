#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider with the fuzzing input data
  FuzzedDataProvider fuzzed_data(data, size);

  // Consume a string from the fuzzed data to create a JSON object
  std::string json_string = fuzzed_data.ConsumeRemainingBytesAsString();

  // Create a JSON object from the string
  struct json_object *jobj = json_tokener_parse(json_string.c_str());

  // If json_tokener_parse returns NULL, it means the string was not a valid JSON
  if (jobj != nullptr) {
    // Call the function-under-test
    double result = json_object_get_double(jobj);

    // Free the JSON object
    json_object_put(jobj);
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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
