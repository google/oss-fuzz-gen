#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_299(const uint8_t *data, size_t size) {
    // Ensure that the size is greater than 0 to avoid passing NULL to sqlite3_msize
    if (size == 0) {
        return 0;
    }

    // Allocate memory and copy the fuzz data into it
    void *memory = sqlite3_malloc(size);
    if (memory == NULL) {
        return 0;
    }

    // Copy the input data into the allocated memory
    memcpy(memory, data, size);

    // Call the function-under-test
    sqlite3_uint64 msize = sqlite3_msize(memory);

    // Free the allocated memory
    sqlite3_free(memory);

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

    LLVMFuzzerTestOneInput_299(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
