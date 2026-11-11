#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Function prototype for janet_getboolean
int janet_getboolean(const Janet *array, int32_t index);

int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an integer index
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Interpret the first part of the data as an integer index
    int32_t index = *(int32_t *)data;

    // Calculate the number of Janet elements we can have
    size_t num_elements = (size - sizeof(int32_t)) / sizeof(Janet);

    // Allocate memory for Janet array
    Janet *janet_array = (Janet *)malloc(num_elements * sizeof(Janet));
    if (janet_array == NULL) {
        return 0;
    }

    // Populate the Janet array with the remaining data
    for (size_t i = 0; i < num_elements; i++) {
        // Ensure we do not read out of bounds
        if (sizeof(int32_t) + i * sizeof(Janet) + sizeof(Janet) <= size) {
            janet_array[i] = *(Janet *)(data + sizeof(int32_t) + i * sizeof(Janet));
        } else {
            janet_array[i] = janet_wrap_nil(); // Default to a safe value
        }
    }

    // Call the function-under-test
    if (index >= 0 && index < num_elements) {
        int result = janet_getboolean(janet_array, index);
    }

    // Free the allocated memory
    free(janet_array);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_184(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
