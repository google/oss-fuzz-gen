#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <stddef.h>
#include <stdint.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    struct json_object *jobj = json_object_new_object();
    if (jobj == nullptr) {
        return 0; // Early exit if object creation fails
    }

    // Consume a string and an integer from the fuzzed data
    std::string key = fuzzed_data.ConsumeRandomLengthString(10);
    int int_value = fuzzed_data.ConsumeIntegral<int>();

    // Ensure the key is not empty to effectively test the function
    if (key.empty()) {
        key = "default_key";
    }

    // Call the function-under-test
    json_object_object_add(jobj, key.c_str(), json_object_new_int(int_value));

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
