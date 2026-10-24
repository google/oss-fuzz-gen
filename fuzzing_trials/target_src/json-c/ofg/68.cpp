#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume an integer from the fuzzed data
    int32_t int_value = fuzzed_data.ConsumeIntegral<int32_t>();

    // Call the function-under-test with the fuzzed integer value
    struct json_object *obj = json_object_new_int(int_value);

    // Clean up the created json_object to prevent memory leaks
    json_object_put(obj);

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
