#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>  // Include for free()
#include <string.h>  // Include for memcpy()
#include <stdio.h>   // Include for printf()

// Function-under-test declaration
void * janet_scalloc(size_t num, size_t size);

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure that we have enough data to extract two size_t values
    if (size < sizeof(size_t) * 2) {
        return 0;
    }

    // Extract two size_t values from the input data
    size_t num;
    size_t elem_size;

    // Use memcpy to safely extract size_t values from the input data
    memcpy(&num, data, sizeof(size_t));
    memcpy(&elem_size, data + sizeof(size_t), sizeof(size_t));

    // Check for potential overflow in multiplication
    if (elem_size != 0 && num > SIZE_MAX / elem_size) {
        return 0;  // Prevent overflow by returning early
    }

    // Call the function-under-test
    void *result = janet_scalloc(num, elem_size);

    // Check if the allocation was successful
    if (result == NULL && num != 0 && elem_size != 0) {
        printf("Allocation failed for num: %zu, elem_size: %zu\n", num, elem_size);
        return 0;
    }

    // Optionally, perform some operations on the allocated memory
    if (result != NULL) {
        // Example operation: write some data to the allocated memory
        memset(result, 0, num * elem_size);

        // Free the allocated memory to prevent memory leaks
        free(result);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_42(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
