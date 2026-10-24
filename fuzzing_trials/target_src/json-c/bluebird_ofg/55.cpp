#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <stdint.h>
#include <string>
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a uint64_t value from the fuzzed data
    uint64_t uint64_value = fuzzed_data.ConsumeIntegral<uint64_t>();

    // Consume a string from the fuzzed data
    std::string string_value = fuzzed_data.ConsumeRandomLengthString();

    // Create a new JSON object and add different types of data
    struct json_object *json_obj = json_object_new_object();
    if (json_obj != nullptr) {
        // Add a uint64_t value to the JSON object
        struct json_object *uint64_obj = json_object_new_uint64(uint64_value);
        json_object_object_add(json_obj, "uint64", uint64_obj);

        // Add a string value to the JSON object
        struct json_object *string_obj = json_object_new_string(string_value.c_str());
        json_object_object_add(json_obj, "string", string_obj);

        // Clean up the created JSON object
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
