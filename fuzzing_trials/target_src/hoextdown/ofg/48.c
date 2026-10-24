#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
void * hoedown_malloc(size_t size);

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Ensure that the size is not zero to avoid undefined behavior
    if (size == 0) {
        return 0;
    }

    // Determine a valid size for allocation, ensuring it's not excessively large
    size_t alloc_size = size < 1024 ? size : 1024; // Limit the allocation size to 1024 bytes

    // Call the function-under-test with the size derived from the input
    void *result = hoedown_malloc(alloc_size);

    // If the allocation is successful, use the allocated memory
    if (result != NULL) {
        // Copy the fuzz input data into the allocated memory
        memcpy(result, data, alloc_size);

        // Use the memory in a meaningful way
        // For example, perform some operations on the allocated memory
        // This is a placeholder for more complex logic that might be tested
        for (size_t i = 0; i < alloc_size; i++) {
            ((uint8_t *)result)[i] ^= 0xFF; // Example operation: bitwise NOT
        }

        // Free the memory after use
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
