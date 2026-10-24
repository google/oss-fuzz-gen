#include <stdint.h>
#include <stddef.h> // Include this for size_t
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 8 bytes to read a 64-bit integer
    if (size < sizeof(sqlite3_int64)) {
        return 0;
    }

    // Read the first 8 bytes of data as an sqlite3_int64 value
    sqlite3_int64 limit = 0;
    for (size_t i = 0; i < sizeof(sqlite3_int64); ++i) {
        limit |= ((sqlite3_int64)data[i]) << (i * 8);
    }

    // Call the function-under-test
    sqlite3_int64 result = sqlite3_soft_heap_limit64(limit);

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_112(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
