#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume bytes to create a JSON object string
    std::string json_str1 = fuzzed_data.ConsumeRandomLengthString(size / 2);
    std::string json_str2 = fuzzed_data.ConsumeRemainingBytesAsString();

    // Parse the strings into JSON objects
    struct json_object *json_obj1 = json_tokener_parse(json_str1.c_str());
    struct json_object *json_obj2 = json_tokener_parse(json_str2.c_str());

    // Ensure both JSON objects are non-NULL
    if (json_obj1 && json_obj2) {
        // Call the function-under-test
        json_object_array_add(json_obj1, json_obj2);
    }

    // Clean up
    if (json_obj1) json_object_put(json_obj1);
    if (json_obj2) json_object_put(json_obj2);

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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
