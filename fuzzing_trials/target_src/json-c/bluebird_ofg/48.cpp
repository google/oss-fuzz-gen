#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the data to create a JSON object string
    std::string json_string = fuzzed_data.ConsumeRandomLengthString(size);

    // Parse the JSON object string into a json_object
    struct json_object *json_obj = json_tokener_parse(json_string.c_str());

    // Check if the json_object was successfully created
    if (json_obj == nullptr) {
        return 0; // Early exit if parsing failed
    }

    // Consume an integer for the flag parameter
    int flags = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    const char *result = json_object_to_json_string_ext(json_obj, flags);

    // Clean up the json_object
    json_object_put(json_obj);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
