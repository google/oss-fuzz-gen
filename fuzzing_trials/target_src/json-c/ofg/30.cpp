#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_types.h"  // Include the correct header for json_type
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>

// Define the maximum value for the json_type enum
const int kMaxJsonTypeValue = json_type_string;

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object from fuzzed data
    std::string json_str = fuzzed_data.ConsumeRandomLengthString(1024);
    struct json_object *jobj = json_tokener_parse(json_str.c_str());

    // Ensure json_object is not NULL
    if (jobj == NULL) {
        return 0;
    }

    // Pick a random json_type from the enum
    json_type json_type_value = static_cast<json_type>(
        fuzzed_data.ConsumeIntegralInRange<int>(0, kMaxJsonTypeValue));

    // Call the function-under-test
    int result = json_object_is_type(jobj, json_type_value);

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
