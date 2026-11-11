#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    char *errMsg = 0;
    char sql[] = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value INTEGER);";
    char insert_sql[] = "INSERT INTO test (value) VALUES (1);";
    char select_sql[] = "SELECT value FROM test WHERE id = ?;";

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Create table
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Insert a row
    rc = sqlite3_exec(db, insert_sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 0;
    }

    // Prepare statement
    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // Use fuzz data as the parameter for the statement
    if (size > 0) {
        int id = data[0] % 256; // Ensure id is within a reasonable range
        sqlite3_bind_int(stmt, 1, id);

        // Execute statement
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            // Call the function-under-test
            sqlite3_int64 value = sqlite3_column_int64(stmt, 0);
            (void)value; // Use the value to avoid unused variable warning
        }
    }

    // Finalize statement and close database
    sqlite3_finalize(stmt);
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

    LLVMFuzzerTestOneInput_287(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
