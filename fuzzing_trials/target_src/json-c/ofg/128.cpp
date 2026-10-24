#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string to create a JSON object
    std::string json_string = fuzzed_data.ConsumeRandomLengthString();
    struct json_object *json_obj = json_tokener_parse(json_string.c_str());

    // Ensure json_obj is not NULL
    if (!json_obj) {
        return 0;
    }

    // Consume an integer for the second parameter
    int flags = fuzzed_data.ConsumeIntegral<int>();

    // Prepare a size_t variable for the third parameter
    size_t length = 0;

    // Call the function-under-test
    const char *result = json_object_to_json_string_length(json_obj, flags, &length);

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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
