#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the input data for a JSON string
    std::string json_str = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes() / 2);

    // Parse the JSON string into a json_object
    struct json_object *json_obj = json_tokener_parse(json_str.c_str());
    if (json_obj == nullptr) {
        return 0; // If parsing fails, exit early
    }

    // Consume the remaining data for the key
    std::string key = fuzzed_data.ConsumeRemainingBytesAsString();

    // Call the function-under-test
    struct json_object *result = json_object_object_get(json_obj, key.c_str());

    // Decrement reference count for the json_object
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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
