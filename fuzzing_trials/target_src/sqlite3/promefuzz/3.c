// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_blob_close at sqlite3.c:90931:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_exec at sqlite3.c:126811:16 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_libversion at sqlite3.c:171116:24 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_column_text at sqlite3.c:79749:33 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_blob *blob = NULL;
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO test (value) VALUES ('A');";
    char *errMsg = 0;
    const char *tail = 0;
    int rc;

    // Write data to a dummy file if needed
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Step 1: Close a NULL blob handle
    rc = sqlite3_blob_close(blob);

    // Step 2: Execute SQL using sqlite3_exec
    rc = sqlite3_open(":memory:", &db);
    if (rc == SQLITE_OK) {
        rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
        if (rc != SQLITE_OK && errMsg) {
            sqlite3_free(errMsg);
        }
    }

    // Step 3: Get SQLite library version
    const char *version = sqlite3_libversion();

    if (db) {
        // Step 4: Prepare a SQL statement
        rc = sqlite3_prepare_v2(db, "SELECT * FROM test;", -1, &stmt, &tail);
        if (rc == SQLITE_OK) {
            // Step 5: Execute the prepared statement
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                // Step 6: Retrieve text from the first column
                const unsigned char *text = sqlite3_column_text(stmt, 0);
            }

            // Step 7: Finalize the statement
            sqlite3_finalize(stmt);
        }

        // Step 8: Close the database
        sqlite3_close(db);
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    