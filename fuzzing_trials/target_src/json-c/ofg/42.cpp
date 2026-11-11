#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <stddef.h>
#include <stdint.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider with input data
  FuzzedDataProvider fuzzed_data(data, size);

  // Create a json_object to pass as the first parameter
  json_object *jobj = json_object_new_object();

  // Consume a string from the fuzzed data for the second parameter
  std::string key = fuzzed_data.ConsumeRandomLengthString();
  const char *key_cstr = key.c_str();

  // Call the function-under-test
  json_object_object_del(jobj, key_cstr);

  // Clean up
  json_object_put(jobj);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
