#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <string>

// Include the correct header for json_tokener_parse_verbose
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);

  // Consume a random length string from the fuzzed data for the JSON input
  std::string json_input = fuzzed_data.ConsumeRandomLengthString();

  // Prepare the error output variable
  enum json_tokener_error error;

  // Call the function-under-test
  struct json_object *json_obj = json_tokener_parse_verbose(json_input.c_str(), &error);

  // Clean up if a valid JSON object was created
  if (json_obj != nullptr) {
    json_object_put(json_obj);
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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
