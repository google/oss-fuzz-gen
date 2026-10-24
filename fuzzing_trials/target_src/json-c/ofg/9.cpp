#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume an int64_t value from the fuzzed data
    int64_t int_value = fuzzed_data.ConsumeIntegral<int64_t>();

    // Call the function-under-test with the consumed int64_t value
    struct json_object *obj = json_object_new_int64(int_value);

    // Convert the JSON object to a string
    const char *json_str = json_object_to_json_string(obj);

    // Parse the JSON string back to a JSON object to test additional functionality
    struct json_object *parsed_obj = json_tokener_parse(json_str);

    // Free the created JSON objects to avoid memory leaks
    json_object_put(obj);
    json_object_put(parsed_obj);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
