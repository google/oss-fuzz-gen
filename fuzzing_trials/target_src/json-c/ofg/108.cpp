#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/json-c/arraylist.h"

// Using the definition of array_list_free_fn and array_list from the included header
// No need to redefine array_list_free_fn or array_list

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a boolean to decide whether to use a null free function or a valid one
    bool use_null_free_fn = fuzzed_data.ConsumeBool();
    array_list_free_fn *free_fn = nullptr;

    if (!use_null_free_fn) {
        // Provide a dummy free function if not using null
        free_fn = [](void *ptr) {
            // Dummy free function, does nothing
        };
    }

    // Consume an integer for the second parameter
    int param = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    struct array_list *result = array_list_new2(free_fn, param);

    // Normally, you would perform some operations on the result here
    // and ensure proper cleanup if necessary.

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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
