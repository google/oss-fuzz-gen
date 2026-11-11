#include <cstdint> // Standard library for uint8_t
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h" // Correct path for json_tokener_error and json_tokener_error_desc
#include "/src/json-c/json_object.h" // Include the json-c library for json_tokener_parse

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the input data as a string for JSON parsing
    std::string json_input = fuzzed_data.ConsumeRandomLengthString();

    // Parse the JSON input
    struct json_object *parsed_json = json_tokener_parse(json_input.c_str());

    // If parsing was successful, free the parsed json object
    if (parsed_json) {
        json_object_put(parsed_json);
    }

    // Consume an integer value within the range of the json_tokener_error enum
    json_tokener_error error_type = 
        static_cast<json_tokener_error>(fuzzed_data.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(json_tokener_error_memory)));

    // Call the function-under-test
    const char *result = json_tokener_error_desc(error_type);

    // Use the result to avoid any compiler optimizations
    if (result) {
        volatile char unused = result[0];
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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
