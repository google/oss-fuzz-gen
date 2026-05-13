#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stddef.h> // Include for size_t

// Function to create a simple in-memory database and prepare a statement
static sqlite3_stmt* prepareStatement(sqlite3 *db) {
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, value TEXT);"
                      "INSERT INTO test (value) VALUES ('Hello');"
                      "SELECT * FROM test;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, 0);
    
    if (rc != SQLITE_OK) {
        return NULL;
    }
    
    const char *select_sql = "SELECT * FROM test;";
    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, 0);
    
    if (rc != SQLITE_OK) {
        return NULL;
    }
    
    return stmt;
}

extern int LLVMFuzzerTestOneInput_322(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    
    // Open an in-memory database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }
    
    // Prepare a statement
    stmt = prepareStatement(db);
    if (stmt == NULL) {
        sqlite3_close(db);
        return 0;
    }
    
    // Execute the statement
    int rc = sqlite3_step(stmt);
    
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

    LLVMFuzzerTestOneInput_322(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
