#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Declare and initialize the variable for sqlite3_int64
    sqlite3_int64 heap_limit = 0;

    // Ensure we have enough data to populate sqlite3_int64
    if (size >= sizeof(sqlite3_int64)) {
        // Copy data into heap_limit, ensuring correct casting
        heap_limit = *((const sqlite3_int64 *)data);
    }

    // Call the function-under-test
    sqlite3_int64 result = sqlite3_soft_heap_limit64(heap_limit);

    // Use the result to avoid compiler optimizations removing the call
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

    LLVMFuzzerTestOneInput_113(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
