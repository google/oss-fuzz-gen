#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a JSON object
    json_object *jobj = json_object_new_array();
    if (!jobj) {
        return 0; // Return if the object creation failed
    }

    // Populate the JSON array with some elements
    size_t array_size = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 10);
    for (size_t i = 0; i < array_size; ++i) {
        json_object_array_add(jobj, json_object_new_int(fuzzed_data.ConsumeIntegral<int>()));
    }

    // Consume indices for deletion
    size_t idx = fuzzed_data.ConsumeIntegralInRange<size_t>(0, array_size - 1);
    size_t count = fuzzed_data.ConsumeIntegralInRange<size_t>(1, array_size - idx);

    // Call the function under test
    json_object_array_del_idx(jobj, idx, count);

    // Clean up
    json_object_put(jobj);

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
