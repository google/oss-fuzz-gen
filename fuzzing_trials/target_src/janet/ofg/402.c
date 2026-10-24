#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function-under-test
void *janet_realloc(void *ptr, size_t size);

int LLVMFuzzerTestOneInput_402(const uint8_t *data, size_t size) {
    // Initialize a non-NULL pointer
    void *ptr = malloc(1); // Allocate a small amount of memory initially

    // Ensure size is non-zero for realloc
    size_t new_size = size > 0 ? size : 1;

    // Call the function-under-test
    void *new_ptr = janet_realloc(ptr, new_size);

    // Free the allocated memory to prevent memory leak
    free(new_ptr);

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

    LLVMFuzzerTestOneInput_402(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
