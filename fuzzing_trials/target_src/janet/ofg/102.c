#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // Include for malloc and free
#include <string.h> // Include for memory operations

// Function-under-test
void * janet_malloc(size_t);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Ensure size is non-zero for malloc and not excessively large
    if (size == 0 || size > 1024) {
        return 0;
    }

    // Call the function-under-test
    void *ptr = janet_malloc(size);

    // Check if the allocation was successful
    if (ptr != NULL) {
        // Use the allocated memory
        memset(ptr, 0, size); // Initialize allocated memory to zero

        // Perform some operations on the memory
        // Copy as much data as possible from input
        size_t copy_size = size < sizeof(uint8_t) ? size : sizeof(uint8_t);
        memcpy(ptr, data, copy_size); // Copy data into allocated memory

        // Free the allocated memory
        free(ptr);
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

    LLVMFuzzerTestOneInput_102(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
