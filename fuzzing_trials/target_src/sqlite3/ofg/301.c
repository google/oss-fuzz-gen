#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_301(const uint8_t *data, size_t size) {
    // Ensure that the input size is not zero and within a reasonable range
    if (size == 0 || size > 1000) {
        return 0;
    }

    // Use the input data to determine the size of memory to allocate
    int alloc_size = (int)(data[0] % 256); // Limit the allocation size to 0-255

    // Call the function-under-test
    void *allocated_memory = sqlite3_malloc(alloc_size);

    // Free the allocated memory if it was successfully allocated
    if (allocated_memory != NULL) {
        sqlite3_free(allocated_memory);
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

    LLVMFuzzerTestOneInput_301(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
