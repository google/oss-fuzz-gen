#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Initialize SQLite database and statement
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result;
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);"
                      "INSERT INTO test (value) VALUES ('test');"
                      "SELECT * FROM test;";

    // Open an in-memory database
    result = sqlite3_open(":memory:", &db);
    if (result != SQLITE_OK) {
        return 0;
    }

    // Execute SQL commands
    result = sqlite3_exec(db, sql, 0, 0, 0);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare the statement
    result = sqlite3_prepare_v2(db, "SELECT * FROM test;", -1, &stmt, 0);
    if (result != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Step through the statement to ensure it is ready for column access
    result = sqlite3_step(stmt);
    if (result != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Use the fuzz data to determine the column index
    int column_index = 0;
    if (size > 0) {
        column_index = data[0] % sqlite3_column_count(stmt);
    }

    // Call the function-under-test
    int column_value = sqlite3_column_int(stmt, column_index);

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

    LLVMFuzzerTestOneInput_153(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
