#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object to be used as the array
    json_object *json_array = json_object_new_array();

    // Ensure there is enough data to consume
    if (fuzzed_data.remaining_bytes() < sizeof(size_t)) {
        json_object_put(json_array);
        return 0;
    }

    // Consume a size_t value for the index
    size_t index = fuzzed_data.ConsumeIntegral<size_t>();

    // Create another json_object to be inserted into the array
    json_object *json_obj = json_object_new_object();

    // Call the function-under-test
    json_object_array_put_idx(json_array, index, json_obj);

    // Clean up
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

    LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
