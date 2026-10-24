#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object with a random integer value
    int64_t initial_value = fuzzed_data.ConsumeIntegral<int64_t>();
    struct json_object *jobj = json_object_new_int64(initial_value);

    // Get another integer to increment the json_object's integer value
    int64_t increment_value = fuzzed_data.ConsumeIntegral<int64_t>();

    // Call the function-under-test
    json_object_int_inc(jobj, increment_value);

    // Clean up by decrementing the reference count of the json_object
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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
