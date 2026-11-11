#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    struct json_object *jobj = json_object_new_array();

    // Populate the json_object array with some elements
    size_t num_elements = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 10);
    for (size_t i = 0; i < num_elements; ++i) {
        int value = fuzzed_data.ConsumeIntegral<int>();
        json_object_array_add(jobj, json_object_new_int(value));
    }

    // Create a sorting function pointer
    int (*sort_fn)(const void *, const void *) = [](const void *a, const void *b) -> int {
        const json_object *obj_a = *(const json_object **)a;
        const json_object *obj_b = *(const json_object **)b;
        int int_a = json_object_get_int(obj_a);
        int int_b = json_object_get_int(obj_b);
        return (int_a > int_b) - (int_a < int_b);
    };

    // Call the function-under-test
    json_object_array_sort(jobj, sort_fn);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
