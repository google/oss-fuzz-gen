#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Function-under-test
void *janet_realloc(void *ptr, size_t size);

int LLVMFuzzerTestOneInput_401(const uint8_t *data, size_t size) {
    // Initialize variables
    void *ptr = NULL;
    size_t new_size;

    // Ensure size is at least the size of a size_t to safely read new_size
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Copy the first sizeof(size_t) bytes from data to new_size
    new_size = *((size_t *)data);

    // Call the function-under-test
    ptr = janet_realloc(ptr, new_size);

    // Free the allocated memory if ptr is not NULL
    if (ptr != NULL) {
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

    LLVMFuzzerTestOneInput_401(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
