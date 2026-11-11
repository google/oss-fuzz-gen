#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);

  // Create a json_object from a string
  std::string json_string = fuzzed_data_provider.ConsumeRandomLengthString();
  struct json_object *source_json = json_tokener_parse(json_string.c_str());

  // Prepare the destination json_object pointer
  struct json_object *dest_json = NULL;

  // Define a shallow copy function with the correct signature
  json_c_shallow_copy_fn *shallow_copy_fn = [](struct json_object *src, struct json_object *parent, const char *key, unsigned long index, struct json_object **dst) -> int {
    *dst = json_object_get(src);
    return (*dst != NULL) ? 0 : -1;
  };

  // Call the function under test
  if (source_json != NULL) {
    json_object_deep_copy(source_json, &dest_json, shallow_copy_fn);
  }

  // Clean up
  if (source_json != NULL) {
    json_object_put(source_json);
  }
  if (dest_json != NULL) {
    json_object_put(dest_json);
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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
