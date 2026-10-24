#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_types.h"

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data.
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string from the fuzzed data.
    std::string json_string = fuzzed_data.ConsumeRandomLengthString();

    // Parse the JSON string to create a json_object.
    struct json_object *json_obj = json_tokener_parse(json_string.c_str());

    // If parsing failed, json_obj will be NULL and we should exit early.
    if (json_obj == nullptr) {
        return 0;
    }

    // Define the maximum value for json_type enumeration.
    const json_type max_json_type_value = json_type_string;

    // Consume an integer in the range of valid json_type enumeration values.
    json_type json_type_value = static_cast<json_type>(
        fuzzed_data.ConsumeIntegralInRange<int>(json_type_null, max_json_type_value));

    // Call the function-under-test with the json_object and json_type.
    int result = json_object_is_type(json_obj, json_type_value);

    // Clean up the json_object.
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
