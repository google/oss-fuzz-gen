// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_errcode at sqlite3.c:173827:16 in sqlite3.h
// sqlite3_extended_errcode at sqlite3.c:173836:16 in sqlite3.h
// sqlite3_set_authorizer at sqlite3.c:110840:16 in sqlite3.h
// sqlite3_collation_needed at sqlite3.c:174822:16 in sqlite3.h
// sqlite3_get_autocommit at sqlite3.c:174945:16 in sqlite3.h
// sqlite3_table_column_metadata at sqlite3.c:175018:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>

static int dummy_authorizer(void *pUserData, int action, const char *param1, const char *param2, const char *param3, const char *param4) {
    return SQLITE_OK;
}

static void dummy_collation_needed(void *pCollNeededArg, sqlite3 *db, int eTextRep, const char *name) {
    // Do nothing for now
}

int LLVMFuzzerTestOneInput_106(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;
    const char *dbName = "main";
    const char *tableName = "test";
    const char *columnName = "id";
    const char *pzDataType = NULL;
    const char *pzCollSeq = NULL;
    int pNotNull = 0, pPrimaryKey = 0, pAutoinc = 0;

    // Initialize SQLite in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a dummy table
    rc = sqlite3_exec(db, "CREATE TABLE test(id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Fuzzing sqlite3_errcode
    int errcode = sqlite3_errcode(db);

    // Fuzzing sqlite3_extended_errcode
    int extended_errcode = sqlite3_extended_errcode(db);

    // Fuzzing sqlite3_set_authorizer
    rc = sqlite3_set_authorizer(db, dummy_authorizer, NULL);

    // Fuzzing sqlite3_collation_needed
    rc = sqlite3_collation_needed(db, NULL, dummy_collation_needed);

    // Fuzzing sqlite3_get_autocommit
    int autocommit = sqlite3_get_autocommit(db);

    // Fuzzing sqlite3_table_column_metadata
    rc = sqlite3_table_column_metadata(db, dbName, tableName, columnName, &pzDataType, &pzCollSeq, &pNotNull, &pPrimaryKey, &pAutoinc);

    // Cleanup
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    