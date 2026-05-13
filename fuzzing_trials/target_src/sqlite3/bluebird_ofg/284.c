#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// This function initializes an SQLite database in memory and returns the database handle
sqlite3* initializeInMemoryDatabase() {
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return NULL;
    }
    return db;
}

int LLVMFuzzerTestOneInput_284(const uint8_t *data, size_t size) {
    // Initialize an in-memory SQLite database
    sqlite3 *db = initializeInMemoryDatabase();
    if (db == NULL) {
        return 0; // Early exit if the database couldn't be initialized
    }

    // Create a dummy SQLite statement
    sqlite3_stmt *stmt;
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, value BLOB)";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Correctly use the statement to execute the SQL
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Use a valid context by executing a SQL statement that uses an aggregate function
    const char *insert_sql = "INSERT INTO test (value) VALUES (?)";
    sqlite3_stmt *insert_stmt;
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Bind the fuzzing data to the statement
    rc = sqlite3_bind_blob(insert_stmt, 1, data, size, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(insert_stmt);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the insert statement
    rc = sqlite3_step(insert_stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(insert_stmt);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Finalize the insert statement
    sqlite3_finalize(insert_stmt);

    // Finalize the statement and close the database
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

    LLVMFuzzerTestOneInput_284(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
