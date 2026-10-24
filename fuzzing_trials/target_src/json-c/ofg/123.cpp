#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    struct json_object *jobj = json_object_new_object();

    // Consume a boolean value
    json_bool bool_value = fuzzed_data.ConsumeBool();

    // Consume a string to use as a key
    std::string key = fuzzed_data.ConsumeRandomLengthString(10);

    // Ensure the key is not empty to effectively test the function
    if (key.empty()) {
        key = "default_key";
    }

    // Call the function-under-test
    json_object_object_add(jobj, key.c_str(), json_object_new_boolean(bool_value));

    // Decrement the reference count of the json object to free it
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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
