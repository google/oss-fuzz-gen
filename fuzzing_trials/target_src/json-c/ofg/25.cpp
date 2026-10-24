#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize the fuzzed data provider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    struct json_object *json_obj = json_object_new_object();
    if (json_obj == nullptr) {
        return 0; // Exit if json_object creation failed
    }

    // Consume an int64_t value for the second parameter
    int64_t int_value = fuzzed_data.ConsumeIntegral<int64_t>();

    // Call the function-under-test
    json_object_set_int64(json_obj, int_value);

    // Clean up the json_object
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
