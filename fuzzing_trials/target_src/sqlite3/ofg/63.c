#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

// Define a simple sqlite3_vfs structure
static sqlite3_vfs simple_vfs = {
    1,                 // iVersion
    sizeof(sqlite3_vfs), // szOsFile
    1024,              // mxPathname
    NULL,              // pNext
    "simple_vfs",      // zName
    NULL,              // pAppData
    NULL,              // xOpen
    NULL,              // xDelete
    NULL,              // xAccess
    NULL,              // xFullPathname
    NULL,              // xDlOpen
    NULL,              // xDlError
    NULL,              // xDlSym
    NULL,              // xDlClose
    NULL,              // xRandomness
    NULL,              // xSleep
    NULL,              // xCurrentTime
    NULL,              // xGetLastError
    NULL,              // xCurrentTimeInt64
    NULL,              // xSetSystemCall
    NULL,              // xGetSystemCall
    NULL               // xNextSystemCall
};

extern int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure that the data size is at least 1 to extract an integer
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to determine the makeDflt parameter
    int makeDflt = data[0] % 2; // 0 or 1

    // Call the function-under-test
    sqlite3_vfs_register(&simple_vfs, makeDflt);

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

    LLVMFuzzerTestOneInput_63(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
