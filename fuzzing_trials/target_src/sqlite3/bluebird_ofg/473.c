#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_473(const uint8_t *data, size_t size) {
    // Initialize SQLite
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // If the database cannot be opened, exit early
    }

    // Create a dummy table
    if (sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);", 0, 0, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0; // If table creation fails, exit early
    }

    // Prepare the insert statement
    sqlite3_stmt *stmt;
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of sqlite3_prepare_v2
    if (sqlite3_prepare_v2(db, "INSERT INTO test (value) VALUES (?);", 1, &stmt, 0) != SQLITE_OK) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        sqlite3_close(db);
        return 0; // If statement preparation fails, exit early
    }

    // Bind the input data to the statement
    if (sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0; // If binding fails, exit early
    }

    // Execute the insert statement
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0; // If execution fails, exit early
    }
    sqlite3_finalize(stmt);

    // Prepare the select statement
    if (sqlite3_prepare_v2(db, "SELECT value FROM test;", -1, &stmt, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return 0; // If statement preparation fails, exit early
    }

    // Execute the select statement and process the result
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Get the value as sqlite3_value
        const unsigned char *text = sqlite3_column_text(stmt, 0);

        // Use the result to avoid unused variable warning
        if (text) {
            // Do something with text, like checking its length
            volatile size_t length = strlen((const char *)text);
        }
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_473(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
