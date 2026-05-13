#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

// Function to create a new sqlite3_value and set it to the input data
sqlite3_value* create_sqlite3_value(const uint8_t *data, size_t size) {
    sqlite3_value *value;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *tail;
    
    // Open a temporary in-memory database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return NULL;
    }
    
    // Prepare a dummy SQL statement
    if (sqlite3_prepare_v2(db, "SELECT ?", -1, &stmt, &tail) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    
    // Bind the input data to the first parameter of the SQL statement
    if (sqlite3_bind_text(stmt, 1, (const char *)data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return NULL;
    }
    
    // Get the value from the bound parameter
    value = (sqlite3_value *)sqlite3_column_value(stmt, 0);
    
    // Finalize the statement and close the database
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return value;
}

int LLVMFuzzerTestOneInput_305(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize SQLite
    sqlite3_initialize();

    // Create a new sqlite3_value and set it to the input data
    sqlite3_value *value = create_sqlite3_value(data, size);
    if (value == NULL) {
        sqlite3_shutdown();
        return 0;
    }

    // Call the function-under-test
    const unsigned char *result = sqlite3_value_text(value);

    // Clean up
    sqlite3_shutdown();

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

    LLVMFuzzerTestOneInput_305(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
