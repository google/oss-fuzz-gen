#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/json-c/arraylist.h" // Include the necessary header for array_list_new2

// Define a dummy free function
void dummy_free_function(void *ptr) {
    // Do nothing
}

// Forward declaration of the function-under-test
struct array_list *array_list_new2(array_list_free_fn *, int);

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the given data and size
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a boolean to decide whether to pass a valid function pointer or NULL
    bool use_valid_function_pointer = fuzzed_data.ConsumeBool();

    // Set the array_list_free_fn pointer based on the consumed boolean
    array_list_free_fn *free_function_ptr = nullptr;
    if (use_valid_function_pointer) {
        free_function_ptr = dummy_free_function;
    }

    // Consume an integer for the second parameter
    int param = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    struct array_list *result = array_list_new2(free_function_ptr, param);

    // Clean up if necessary (depends on the implementation of array_list_new2)
    // For example, if array_list_new2 allocates memory, you might need to free it here.
    if (result != nullptr) {
        // Assuming there's a function to free the array_list, e.g., array_list_free
        array_list_free(result);
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

    LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
