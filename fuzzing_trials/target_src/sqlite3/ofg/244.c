#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

// Define a custom VFS structure for testing
static sqlite3_vfs test_vfs = {
    1,                  // iVersion
    0,                  // szOsFile
    1024,               // mxPathname
    NULL,               // pNext
    "test_vfs",         // zName
    NULL,               // pAppData
    NULL,               // xOpen
    NULL,               // xDelete
    NULL,               // xAccess
    NULL,               // xFullPathname
    NULL,               // xDlOpen
    NULL,               // xDlError
    NULL,               // xDlSym
    NULL,               // xDlClose
    NULL,               // xRandomness
    NULL,               // xSleep
    NULL,               // xCurrentTime
    NULL,               // xGetLastError
    NULL,               // xCurrentTimeInt64
    NULL,               // xSetSystemCall
    NULL,               // xGetSystemCall
    NULL,               // xNextSystemCall
};

int LLVMFuzzerTestOneInput_244(const uint8_t *data, size_t size) {
    // Register the test VFS if not already registered
    if (sqlite3_vfs_find("test_vfs") == NULL) {
        sqlite3_vfs_register(&test_vfs, 0);
    }

    // Unregister the test VFS
    sqlite3_vfs_unregister(&test_vfs);

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

    LLVMFuzzerTestOneInput_244(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
