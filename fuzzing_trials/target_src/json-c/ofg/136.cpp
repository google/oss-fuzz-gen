#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string for the first json_object
    std::string json1_str = fuzzed_data.ConsumeRandomLengthString(size / 2);
    struct json_object *json1 = json_tokener_parse(json1_str.c_str());
    if (json1 == nullptr) {
        return 0;
    }

    // Consume a random length string for the second json_object
    std::string json2_str = fuzzed_data.ConsumeRandomLengthString(size / 2);
    struct json_object *json2 = json_tokener_parse(json2_str.c_str());
    if (json2 == nullptr) {
        json_object_put(json1);
        return 0;
    }

    // Define a comparison function using json_object_equal
    auto compare_func = [](const void *a, const void *b) -> int {
        struct json_object *json_a = *(struct json_object **)a;
        struct json_object *json_b = *(struct json_object **)b;
        return json_object_equal(json_a, json_b) ? 0 : 1;
    };

    // Call the function-under-test
    struct json_object *result = json_object_array_bsearch(json1, json2, compare_func);

    // Cleanup
    json_object_put(json1);
    json_object_put(json2);
    if (result != nullptr) {
        json_object_put(result);
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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
