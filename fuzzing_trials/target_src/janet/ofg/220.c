#include <stdint.h>
#include <stddef.h>
#include <janet.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_220(const uint8_t *data, size_t size) {
    // Ensure there's enough data for at least one Janet value and an int32_t
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Calculate the number of Janet elements we can safely use
    size_t num_elements = (size - sizeof(int32_t)) / sizeof(Janet);

    // Create a buffer for Janet values, ensuring it's properly aligned
    Janet *janet_array = (Janet *)malloc(num_elements * sizeof(Janet));
    if (!janet_array) {
        return 0; // Handle allocation failure
    }

    // Copy the input data into the Janet array buffer
    memcpy(janet_array, data, num_elements * sizeof(Janet));

    // Use the first int32_t from the remaining data for the index
    int32_t index = *((const int32_t *)(data + num_elements * sizeof(Janet)));

    // Ensure the index is within bounds
    if (num_elements > 0) {
        index = index % num_elements;
        if (index < 0) {
            index += num_elements; // Ensure positive index
        }

        // Check if the element at the index is a string
        if (janet_checktype(janet_array[index], JANET_STRING)) {
            // Call the function-under-test with the correct number of arguments
            const char *result = janet_getcstring(janet_array, index);

            // Use the result in some way to avoid compiler optimizations
            if (result) {
                // Do something with the result, e.g., check its length
                size_t len = 0;
                while (result[len] != '\0') {
                    len++;
                }
            }
        }
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

    LLVMFuzzerTestOneInput_220(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
