#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string from the fuzzed data for the JSON input
    std::string json_input = fuzzed_data.ConsumeRandomLengthString();

    // Create a variable for the json_tokener_error
    enum json_tokener_error error;

    // Call the function-under-test with the consumed JSON input and error pointer
    struct json_object *result = json_tokener_parse_verbose(json_input.c_str(), &error);

    // Free the json_object if it was successfully created
    if (result != nullptr) {
        json_object_put(result);
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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
