// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_changes64 at sqlite3.c:172151:26 in sqlite3.h
// sqlite3_total_changes64 at sqlite3.c:172167:26 in sqlite3.h
// sqlite3_last_insert_rowid at sqlite3.c:172123:25 in sqlite3.h
// sqlite3_set_last_insert_rowid at sqlite3.c:172136:17 in sqlite3.h
// sqlite3_update_hook at sqlite3.c:173372:18 in sqlite3.h
// sqlite3_wal_hook at sqlite3.c:173527:18 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static void dummy_update_hook(void *pArg, int operation, const char *dbName, const char *tableName, sqlite3_int64 rowId) {
    // Dummy update hook callback
}

static int dummy_wal_hook(void *pArg, sqlite3 *db, const char *dbName, int nPages) {
    // Dummy WAL hook callback
    return SQLITE_OK;
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a connection to an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Set up the necessary environment
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, &errMsg);
    sqlite3_exec(db, "INSERT INTO test(value) VALUES('fuzzing');", NULL, NULL, &errMsg);
    sqlite3_exec(db, "UPDATE test SET value = 'updated' WHERE id = 1;", NULL, NULL, &errMsg);

    // Fuzz sqlite3_changes64
    sqlite3_int64 changes = sqlite3_changes64(db);
    (void)changes; // Suppress unused variable warning

    // Fuzz sqlite3_total_changes64
    sqlite3_int64 totalChanges = sqlite3_total_changes64(db);
    (void)totalChanges; // Suppress unused variable warning

    // Fuzz sqlite3_last_insert_rowid
    sqlite3_int64 lastRowId = sqlite3_last_insert_rowid(db);
    (void)lastRowId; // Suppress unused variable warning

    // Fuzz sqlite3_set_last_insert_rowid
    sqlite3_set_last_insert_rowid(db, 12345);

    // Fuzz sqlite3_update_hook
    sqlite3_update_hook(db, dummy_update_hook, NULL);

    // Fuzz sqlite3_wal_hook
    sqlite3_wal_hook(db, dummy_wal_hook, NULL);

    // Clean up and close the database connection
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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    