#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Dummy callback function to be used as xDestroy
void dummyDestroy(void *p) {
    // Do nothing
}

// Dummy sqlite3_module structure
static const sqlite3_module dummyModule = {
    0,                          // iVersion
    NULL,                       // xCreate
    NULL,                       // xConnect
    NULL,                       // xBestIndex
    NULL,                       // xDisconnect
    NULL,                       // xDestroy
    NULL,                       // xOpen
    NULL,                       // xClose
    NULL,                       // xFilter
    NULL,                       // xNext
    NULL,                       // xEof
    NULL,                       // xColumn
    NULL,                       // xRowid
    NULL,                       // xUpdate
    NULL,                       // xBegin
    NULL,                       // xSync
    NULL,                       // xCommit
    NULL,                       // xRollback
    NULL,                       // xFindFunction
    NULL,                       // xRename
    NULL,                       // xSavepoint
    NULL,                       // xRelease
    NULL,                       // xRollbackTo
    NULL,                       // xShadowName
};

int LLVMFuzzerTestOneInput_281(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize SQLite database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a module name from the input data
    char moduleName[256];
    size_t moduleNameLen = size < 255 ? size : 255;
    memcpy(moduleName, data, moduleNameLen);
    moduleName[moduleNameLen] = '\0';

    // Call the function-under-test
    sqlite3_create_module_v2(db, moduleName, &dummyModule, NULL, dummyDestroy);

    // Close the SQLite database
    sqlite3_close(db);

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

    LLVMFuzzerTestOneInput_281(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
