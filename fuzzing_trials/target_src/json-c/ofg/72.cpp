#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the input data to create the first JSON object
    std::string first_json_string = fuzzed_data.ConsumeRandomLengthString(size / 2);
    struct json_object *json_obj1 = json_tokener_parse(first_json_string.c_str());

    // Consume the remaining input data to create the second JSON object
    std::string second_json_string = fuzzed_data.ConsumeRemainingBytesAsString();
    struct json_object *json_obj2 = json_tokener_parse(second_json_string.c_str());

    if (json_obj1 && json_obj2) {
        // Call the function-under-test
        json_object_equal(json_obj1, json_obj2);
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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
