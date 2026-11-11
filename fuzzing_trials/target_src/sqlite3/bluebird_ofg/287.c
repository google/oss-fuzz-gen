#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
    // Initialize SQLite
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Prepare a statement with a single parameter
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT ?;", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0; // If preparing the statement fails, exit early
    }

    // Bind the input data as a blob to the statement
    if (sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0; // If binding the blob fails, exit early
    }

    // Execute the statement
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Retrieve the result as text
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        // Optionally, do something with `text` here
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

    LLVMFuzzerTestOneInput_287(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
