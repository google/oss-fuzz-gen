#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the provided data and size
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object to be used as the array
    json_object *array_obj = json_object_new_array();

    // Create a json_object to be inserted with more varied content
    json_object *insert_obj = json_object_new_object();
    if (fuzzed_data.remaining_bytes() > 0) {
        std::string key = fuzzed_data.ConsumeRandomLengthString(10);
        std::string value = fuzzed_data.ConsumeRandomLengthString(20);
        json_object_object_add(insert_obj, key.c_str(), json_object_new_string(value.c_str()));
    }

    // Consume a size_t value for the index, ensuring it's within bounds
    size_t index = fuzzed_data.ConsumeIntegralInRange<size_t>(0, json_object_array_length(array_obj) + 1);

    // Call the function-under-test
    json_object_array_put_idx(array_obj, index, insert_obj);

    // Decrement the reference count of the json_object array to prevent memory leaks
    json_object_put(array_obj);

    // Note: No need to put insert_obj as json_object_array_put_idx takes ownership

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
