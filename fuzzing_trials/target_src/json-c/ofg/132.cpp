#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    struct json_object *json_obj = json_object_new_object();
    if (json_obj == nullptr) {
        return 0; // Return early if json_object creation fails
    }

    // Consume a uint64_t value from the fuzzed data
    uint64_t uint64_value = fuzzed_data.ConsumeIntegral<uint64_t>();

    // Consume a string key from the fuzzed data
    std::string key = fuzzed_data.ConsumeRandomLengthString(10);
    if (key.empty()) {
        key = "default_key"; // Ensure the key is not empty
    }

    // Call the function-under-test with a key and value
    json_object_object_add(json_obj, key.c_str(), json_object_new_uint64(uint64_value));

    // Decrement reference count for json_obj
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
