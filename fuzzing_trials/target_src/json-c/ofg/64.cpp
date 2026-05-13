#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the data to create a JSON string
    std::string json_str = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes());

    // Parse the JSON string to create a json_object
    struct json_object *json_obj = json_tokener_parse(json_str.c_str());

    // Consume a small portion of the data to create a key string
    std::string key = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100));

    // Prepare a pointer for the output json_object
    struct json_object *output_obj = nullptr;

    // Call the function-under-test
    json_object_object_get_ex(json_obj, key.c_str(), &output_obj);

    // Clean up
    if (json_obj) {
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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
