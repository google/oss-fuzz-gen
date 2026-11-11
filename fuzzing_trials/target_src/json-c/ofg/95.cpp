#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h" // Correct path for json-c library

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume an integer value for the function parameter
    int array_size = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test with the fuzzed parameter
    struct json_object *json_array = json_object_new_array_ext(array_size);

    // Clean up the created json_object to prevent memory leaks
    if (json_array != nullptr) {
        json_object_put(json_array);
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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
