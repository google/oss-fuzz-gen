#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_object.h" // Corrected path for json_object.h
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string> // Include string library for std::string

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the data to create a string input for the function
    std::string json_string = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes());

    // Create a json_tokener object
    struct json_tokener *tok = json_tokener_new();
    if (tok == nullptr) {
        return 0; // Return if tokener creation failed
    }

    // Call the function-under-test
    struct json_object *result = json_tokener_parse_ex(tok, json_string.c_str(), json_string.size());

    // Clean up
    if (result != nullptr) {
        json_object_put(result);
    }
    json_tokener_free(tok);

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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
