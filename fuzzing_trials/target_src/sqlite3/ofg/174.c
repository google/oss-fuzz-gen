#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

// Dummy function to serve as a user-defined function
void dummyFunc_174(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    // Extract an unsigned int from the first argument
    if (argc > 0) {
        unsigned int subtype = (unsigned int)sqlite3_value_int(argv[0]);
        sqlite3_result_subtype(ctx, subtype);
    }
}

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Create an in-memory SQLite database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Create a statement to prepare
    sqlite3_stmt *stmt;
    const char *sql = "SELECT dummyFunc_174(?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Bind the input data as an integer to the statement
    unsigned int value = *(unsigned int *)data;
    sqlite3_bind_int(stmt, 1, (int)value);

    // Execute the statement
    sqlite3_step(stmt);

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

    LLVMFuzzerTestOneInput_174(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
