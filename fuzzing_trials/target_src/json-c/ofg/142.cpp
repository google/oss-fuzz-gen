#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object for the array
    struct json_object *array = json_object_new_array();

    // Create a json_object for the element to be inserted
    struct json_object *element = json_object_new_object();
    if (fuzzed_data.remaining_bytes() > 0) {
        std::string key = fuzzed_data.ConsumeRandomLengthString(10);
        std::string value = fuzzed_data.ConsumeRandomLengthString(10);
        if (!key.empty() && !value.empty()) {
            json_object_object_add(element, key.c_str(), json_object_new_string(value.c_str()));
        }
    }

    // Determine the index to insert the element
    size_t index = fuzzed_data.ConsumeIntegral<size_t>();

    // Call the function-under-test
    json_object_array_put_idx(array, index, element);

    // Clean up
    json_object_put(array);

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

    LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
