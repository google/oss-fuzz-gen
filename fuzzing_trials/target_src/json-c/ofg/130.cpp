#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a JSON array object
    struct json_object *json_array = json_object_new_array();
    if (!json_array) {
        return 0; // If creation fails, return early
    }

    // Determine the number of elements to add to the JSON array
    size_t num_elements = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 100);

    // Populate the JSON array with random integers
    for (size_t i = 0; i < num_elements; ++i) {
        int random_value = fuzzed_data.ConsumeIntegral<int>();
        json_object_array_add(json_array, json_object_new_int(random_value));
    }

    // Get the index to delete from the array
    size_t idx_to_delete = fuzzed_data.ConsumeIntegralInRange<size_t>(0, num_elements - 1);

    // Get the count of elements to delete
    size_t count_to_delete = fuzzed_data.ConsumeIntegralInRange<size_t>(1, num_elements - idx_to_delete);

    // Call the function-under-test
    json_object_array_del_idx(json_array, idx_to_delete, count_to_delete);

    // Free the JSON object
    json_object_put(json_array);

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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
