#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_511(const uint8_t *data, size_t size) {
    void *ptr = NULL;
    sqlite3_uint64 newSize;

    if (size >= sizeof(sqlite3_uint64)) {
        // Use the first part of data as the new size
        newSize = *((sqlite3_uint64 *)data);

        // Allocate initial memory
        ptr = sqlite3_malloc64(1); // Allocate a small initial block

        // Call the function under test
        void *newPtr = sqlite3_realloc64(ptr, newSize);

        // Free the allocated memory
        sqlite3_free(newPtr);
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

    LLVMFuzzerTestOneInput_511(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
