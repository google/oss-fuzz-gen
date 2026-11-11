#include <stdint.h>
#include <stddef.h>  // Include this header to define size_t
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_316(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + 2 * sizeof(sqlite3_int64)) {
        return 0;
    }

    int op = *(int *)data;
    sqlite3_int64 current = *(sqlite3_int64 *)(data + sizeof(int));
    sqlite3_int64 highwater = *(sqlite3_int64 *)(data + sizeof(int) + sizeof(sqlite3_int64));
    int resetFlag = *(int *)(data + sizeof(int) + 2 * sizeof(sqlite3_int64));

    // Ensure pointers are not NULL
    sqlite3_int64 *pCurrent = &current;
    sqlite3_int64 *pHighwater = &highwater;

    // Call the function-under-test
    sqlite3_status64(op, pCurrent, pHighwater, resetFlag);

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

    LLVMFuzzerTestOneInput_316(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
