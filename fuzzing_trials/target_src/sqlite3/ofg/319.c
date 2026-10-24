#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_319(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *sql = "CREATE TABLE IF NOT EXISTS test (id INTEGER, value TEXT); INSERT INTO test (id, value) VALUES (1, 'test');";
    const char *tail;
    
    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    // Execute SQL to create table and insert data
    rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    // Prepare a statement
    rc = sqlite3_prepare_v2(db, "SELECT * FROM test;", -1, &stmt, &tail);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    // Use the data as an index for sqlite3_column_decltype
    if (size > 0) {
        int index = data[0] % sqlite3_column_count(stmt);
        const char *decltype = sqlite3_column_decltype(stmt, index);
        if (decltype) {
            printf("Column decltype: %s\n", decltype);
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

    LLVMFuzzerTestOneInput_319(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
