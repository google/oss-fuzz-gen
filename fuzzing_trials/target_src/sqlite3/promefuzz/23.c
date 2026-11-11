// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_mprintf at sqlite3.c:19329:18 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_mprintf at sqlite3.c:19329:18 in sqlite3.h
// sqlite3_mprintf at sqlite3.c:19329:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_blob_open at sqlite3.c:90692:16 in sqlite3.h
// sqlite3_blob_close at sqlite3.c:90931:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static int dummy_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_blob *blob = NULL;
    char *errMsg = NULL;
    char *sql = NULL;
    int rc;

    // Open a database connection
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy statement
    rc = sqlite3_prepare_v2(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    // Finalize a prepared statement
    rc = sqlite3_finalize(NULL);

    // Execute SQL statement
    if (Size > 0) {
        // Ensure Data is null-terminated for sqlite3_mprintf
        char *safeData = (char *)malloc(Size + 1);
        if (safeData) {
            memcpy(safeData, Data, Size);
            safeData[Size] = '\0';

            sql = sqlite3_mprintf("INSERT INTO test (data) VALUES (%Q);", safeData);
            rc = sqlite3_exec(db, sql, dummy_callback, 0, &errMsg);
            sqlite3_free(sql);
            sqlite3_free(errMsg);
            free(safeData);
        }
    }

    // Use sqlite3_mprintf to create a formatted string
    char *formatted1 = sqlite3_mprintf("Formatted string: %s", "test1");
    char *formatted2 = sqlite3_mprintf("Formatted string: %s", "test2");

    // Free the formatted strings
    sqlite3_free(formatted1);
    sqlite3_free(formatted2);

    // Open a BLOB
    if (Size > 0) {
        rc = sqlite3_blob_open(db, "main", "test", "data", 1, 0, &blob);
        if (rc == SQLITE_OK) {
            sqlite3_blob_close(blob);
        }
    }

    // Close the database connection
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    