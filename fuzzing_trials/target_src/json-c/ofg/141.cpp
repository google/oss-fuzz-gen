#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <string>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Create a FuzzedDataProvider to manage the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume the remaining bytes as a string to create a JSON object
    std::string json_str = fuzzed_data.ConsumeRemainingBytesAsString();

    // Parse the string into a JSON object
    struct json_object *json_obj = json_tokener_parse(json_str.c_str());

    // Ensure the json_obj is not NULL
    if (json_obj != NULL) {
        // Call the function-under-test
        int64_t result = json_object_get_int64(json_obj);

        // Clean up the json object
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

    LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
