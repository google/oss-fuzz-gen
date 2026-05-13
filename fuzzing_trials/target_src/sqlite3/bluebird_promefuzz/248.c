#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include "sqlite3.h"

static int dummy_xCreate(sqlite3 *db, void *pAux, int argc, const char *const*argv, sqlite3_vtab **ppVTab, char **pzErr) {
    return SQLITE_OK;
}

static int dummy_xConnect(sqlite3 *db, void *pAux, int argc, const char *const*argv, sqlite3_vtab **ppVTab, char **pzErr) {
    return SQLITE_OK;
}

static int dummy_xBestIndex(sqlite3_vtab *pVTab, sqlite3_index_info *info) {
    return SQLITE_OK;
}

static int dummy_xDisconnect(sqlite3_vtab *pVTab) {
    return SQLITE_OK;
}

static int dummy_xDestroy(sqlite3_vtab *pVTab) {
    return SQLITE_OK;
}

static sqlite3_module dummyModule = {
    1,
    dummy_xCreate,
    dummy_xConnect,
    dummy_xBestIndex,
    dummy_xDisconnect,
    dummy_xDestroy,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static void dummyDestructor(void *p) {
    // No-op destructor
}

int LLVMFuzzerTestOneInput_248(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Fuzzing sqlite3_create_module
    const char *moduleName = "dummy_module";
    rc = sqlite3_create_module(db, moduleName, &dummyModule, NULL);

    // Fuzzing sqlite3_drop_modules
    const char *keepList[] = {moduleName, NULL};
    rc = sqlite3_drop_modules(db, NULL); // Drop all
    rc = sqlite3_drop_modules(db, keepList); // Keep the dummy module

    // Fuzzing sqlite3_declare_vtab
    const char *createSQL = "CREATE TABLE x(a, b)";
    rc = sqlite3_declare_vtab(db, createSQL);

    // Fuzzing sqlite3_vtab_config
    rc = sqlite3_vtab_config(db, SQLITE_VTAB_CONSTRAINT_SUPPORT, 1);

    // Fuzzing sqlite3_create_module_v2
    rc = sqlite3_create_module_v2(db, moduleName, &dummyModule, NULL, dummyDestructor);

    // Fuzzing sqlite3_create_function
    rc = sqlite3_create_function(db, "dummy_func", 1, SQLITE_UTF8, NULL, NULL, NULL, NULL);

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

    LLVMFuzzerTestOneInput_248(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
