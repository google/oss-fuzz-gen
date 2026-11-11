#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

// Define a dummy destructor function to satisfy the function signature
void dummy_destructor_328(void *data) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_328(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);";
    const char *insert_sql = "INSERT INTO test (value) VALUES (?);";
    int rc;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Execute SQL to create a table
    rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Ensure the data is null-terminated
    char *text_data = (char *)malloc(size + 1);
    if (text_data == NULL) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }
    memcpy(text_data, data, size);
    text_data[size] = '\0';

    // Bind the text data to the SQL statement
    sqlite3_bind_text64(stmt, 1, text_data, (sqlite3_uint64)size, dummy_destructor_328, SQLITE_UTF8);

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(text_data);

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

    LLVMFuzzerTestOneInput_328(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
