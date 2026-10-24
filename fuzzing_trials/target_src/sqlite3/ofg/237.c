#include <stdint.h>
#include <sqlite3.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Early exit if there's no data to process
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql_create_insert = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, data BLOB);"
                                    "INSERT INTO test (data) VALUES (?);";
    const char *sql_select = "SELECT data FROM test WHERE id = 1;";

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare the SQL statement for creating table and inserting data
    rc = sqlite3_exec(db, "BEGIN TRANSACTION;", 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    rc = sqlite3_exec(db, sql_create_insert, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        sqlite3_close(db);
        return 0;
    }

    // Prepare the SQL statement for inserting data
    rc = sqlite3_prepare_v2(db, "INSERT INTO test (data) VALUES (?);", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        sqlite3_close(db);
        return 0;
    }

    // Bind the blob data
    sqlite3_uint64 blob_size = (sqlite3_uint64)size;
    rc = sqlite3_bind_blob64(stmt, 1, (const void *)data, blob_size, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement to insert data
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
        sqlite3_close(db);
        return 0;
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Commit the transaction
    rc = sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare the SQL statement for selecting data
    rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement to select data
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Retrieve the data to ensure the operation was successful
        const void *retrieved_data = sqlite3_column_blob(stmt, 0);
        int retrieved_size = sqlite3_column_bytes(stmt, 0);

        // Optionally, verify the retrieved data matches the input data
        if (retrieved_data && retrieved_size == size && memcmp(retrieved_data, data, size) == 0) {
            // Successfully retrieved and verified the data
        }
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Close the database
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

    LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
