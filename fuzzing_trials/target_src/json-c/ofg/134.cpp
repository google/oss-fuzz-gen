#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the given data and size
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the input data to create a JSON string
    std::string json_str = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes() / 2);

    // Parse the JSON string to create a json_object
    struct json_object *json_obj = json_tokener_parse(json_str.c_str());

    // Ensure the json_object is valid
    if (json_obj == nullptr) {
        return 0;
    }

    // Consume the remaining bytes as a string for the key
    std::string key = fuzzed_data.ConsumeRemainingBytesAsString();

    // Call the function-under-test
    struct json_object *result = json_object_object_get(json_obj, key.c_str());

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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
