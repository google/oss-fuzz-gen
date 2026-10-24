#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a 64-bit integer
    if (size < sizeof(sqlite3_uint64)) {
        return 0;
    }

    // Extract a 64-bit integer from the input data
    sqlite3_uint64 alloc_size = *(const sqlite3_uint64 *)data;

    // Call the function-under-test
    void *memory = sqlite3_malloc64(alloc_size);

    // If memory allocation was successful, free the allocated memory
    if (memory != NULL) {
        sqlite3_free(memory);
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

    LLVMFuzzerTestOneInput_196(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
