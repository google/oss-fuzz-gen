#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

// Function to create a dummy sqlite3_stmt object for testing
sqlite3_stmt* create_dummy_stmt() {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    const char *sql = "SELECT * FROM dummy_table WHERE col1 = ?1 AND col2 = ?2";

    // Open an in-memory database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return NULL;
    }

    // Prepare a dummy statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

    return stmt;
}

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    // Ensure there's at least one byte for a null-terminated string
    if (size == 0) {
        return 0;
    }

    // Create a dummy sqlite3_stmt object
    sqlite3_stmt *stmt = create_dummy_stmt();
    if (stmt == NULL) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *param_name = (char *)malloc(size + 1);
    if (param_name == NULL) {
        sqlite3_finalize(stmt);
        return 0;
    }
    memcpy(param_name, data, size);
    param_name[size] = '\0';

    // Call the function-under-test
    int index = sqlite3_bind_parameter_index(stmt, param_name);

    // Clean up
    free(param_name);
    sqlite3_finalize(stmt);

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

    LLVMFuzzerTestOneInput_208(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
