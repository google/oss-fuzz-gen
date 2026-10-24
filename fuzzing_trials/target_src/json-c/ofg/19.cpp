#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    struct json_object *json_obj = json_object_new_array();
    if (json_obj == nullptr) {
        return 0; // If creation fails, exit early
    }

    // Determine the number of elements to add to the array
    size_t num_elements = fuzzed_data.ConsumeIntegralInRange<size_t>(0, 100);

    // Add elements to the json array
    for (size_t i = 0; i < num_elements; ++i) {
        // Create a new integer json object
        int value = fuzzed_data.ConsumeIntegral<int>();
        struct json_object *int_obj = json_object_new_int(value);
        if (int_obj == nullptr) {
            json_object_put(json_obj);
            return 0; // If creation fails, clean up and exit early
        }
        json_object_array_add(json_obj, int_obj);
    }

    // Consume an integer for the second parameter
    int new_length = fuzzed_data.ConsumeIntegralInRange<int>(0, num_elements);

    // Call the function-under-test
    json_object_array_shrink(json_obj, new_length);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
