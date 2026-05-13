#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_156(const uint8_t *Data, size_t Size) {
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_156(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
