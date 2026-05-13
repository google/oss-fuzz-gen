#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

// User-defined function that will be called by SQLite
static void test_function(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    // Call the function-under-test
    sqlite3_result_error_toobig(ctx);
}

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a new in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Create a user-defined function
    sqlite3_create_function(db, "test_function", 0, SQLITE_UTF8, NULL, test_function, NULL, NULL);

    // Prepare and execute a SQL statement that calls the user-defined function
    const char *sql = "SELECT test_function();";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    // Close the database connection
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

    LLVMFuzzerTestOneInput_71(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
