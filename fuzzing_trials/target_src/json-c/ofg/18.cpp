#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with input data
    FuzzedDataProvider fuzzed_data_provider(data, size);

    // Create a json_object
    struct json_object *json_obj1 = json_object_new_object();
    struct json_object *json_obj2 = json_object_new_object();

    // Consume a string for the key
    std::string key = fuzzed_data_provider.ConsumeRandomLengthString(100);

    // Ensure the key is not empty
    if (key.empty()) {
        json_object_put(json_obj1);
        json_object_put(json_obj2);
        return 0;
    }

    // Call the function-under-test
    json_object_object_add(json_obj1, key.c_str(), json_obj2);

    // Clean up
    json_object_put(json_obj1);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
