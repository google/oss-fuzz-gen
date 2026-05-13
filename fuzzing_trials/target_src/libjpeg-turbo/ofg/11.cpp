#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    // Function-under-test
    void * tj3Alloc(size_t);
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Define a size for allocation, ensuring it's not zero
    size_t alloc_size = size > 0 ? size : 1;

    // Call the function-under-test
    void *allocated_memory = tj3Alloc(alloc_size);

    // Utilize the allocated memory if not NULL
    if (allocated_memory != NULL) {
        // Fill the allocated memory with the input data or a pattern
        // Ensure we don't read beyond the provided data
        size_t copy_size = alloc_size < size ? alloc_size : size;
        memcpy(allocated_memory, data, copy_size);

        // Free the allocated memory
        free(allocated_memory);
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
