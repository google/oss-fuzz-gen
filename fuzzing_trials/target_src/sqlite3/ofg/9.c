#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    void *ptr = NULL;
    sqlite3_uint64 newSize;

    // Ensure that the size is not zero to avoid reallocating a NULL pointer to zero size
    if (size < sizeof(sqlite3_uint64)) {
        return 0;
    }

    // Use the first part of the data to determine the new size for reallocation
    newSize = *((sqlite3_uint64 *)data);

    // Allocate an initial block of memory
    ptr = malloc(1); // Allocate a small initial block

    // Call the function-under-test
    ptr = sqlite3_realloc64(ptr, newSize);

    // Free the allocated memory if realloc succeeded
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

    LLVMFuzzerTestOneInput_9(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
