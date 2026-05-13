#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include "/src/json-c/arraylist.h"  // Include the necessary header for array_list_new

// Function-under-test
struct array_list * array_list_new(array_list_free_fn *);

// Fuzzing harness
extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a boolean to decide whether to pass a non-null function pointer
    bool use_free_fn = fuzzed_data.ConsumeBool();

    // Define a simple free function
    struct FreeFn {
        static void free(void *ptr) {
            // Example free function logic
            if (ptr) {
                // Free the memory or perform any cleanup
            }
        }
    };

    // Call the function-under-test with a valid function pointer or nullptr
    struct array_list *list = array_list_new(use_free_fn ? &FreeFn::free : nullptr);

    // Normally, we would perform some operations on the list and free it
    // However, since this is a fuzzing harness, we just return 0
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
