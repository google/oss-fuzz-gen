#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <string>

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Create a FuzzedDataProvider to handle the input data
    FuzzedDataProvider fuzzed_data_provider(data, size);

    // Create a JSON object
    struct json_object *json_obj = json_object_new_object();

    // Use some of the fuzzed data to create a string
    std::string key = fuzzed_data_provider.ConsumeRandomLengthString(10);
    std::string value = fuzzed_data_provider.ConsumeRandomLengthString(50);

    // Add the key-value pair to the JSON object
    json_object_object_add(json_obj, key.c_str(), json_object_new_string(value.c_str()));

    // Clean up the created JSON object
    if (json_obj != nullptr) {
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
