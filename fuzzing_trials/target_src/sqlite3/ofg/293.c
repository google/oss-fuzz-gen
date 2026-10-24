#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_293(const uint8_t *data, size_t size) {
    // Ensure we have at least 8 bytes to interpret as an int and a string
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the input data
    int milliseconds = *(const int *)data;

    // Ensure the milliseconds value is positive to make the call meaningful
    if (milliseconds < 0) {
        return 0;
    }

    // Initialize SQLite database in memory
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a simple table
    const char *sql_create_table = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);";
    char *err_msg = NULL;
    if (sqlite3_exec(db, sql_create_table, 0, 0, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 0;
    }

    // Insert a value using the fuzz data as the value, starting from the fifth byte
    const char *sql_insert = "INSERT INTO test (value) VALUES (?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql_insert, -1, &stmt, 0) == SQLITE_OK) {
        // Ensure we have enough data to insert
        if (size > sizeof(int)) {
            sqlite3_bind_text(stmt, 1, (const char *)(data + sizeof(int)), size - sizeof(int), SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_text(stmt, 1, "", 0, SQLITE_TRANSIENT);
        }
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Query the table to ensure the data was inserted
    const char *sql_select = "SELECT * FROM test;";
    if (sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            // Accessing the data to ensure the query is executed
            const unsigned char *value = sqlite3_column_text(stmt, 1);
            (void)value; // Use the value to prevent unused variable warning
        }
        sqlite3_finalize(stmt);
    }

    // Sleep for the extracted milliseconds
    sqlite3_sleep(milliseconds);

    // Clean up and close the database
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

    LLVMFuzzerTestOneInput_293(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
