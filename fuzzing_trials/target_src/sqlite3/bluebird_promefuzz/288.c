#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_288(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    int rc;

    // Initialize SQLite in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy file for SQL input
    write_dummy_file(Data, Size);

    // Prepare SQL statement
    rc = sqlite3_prepare_v2(db, (const char *)Data, Size, &stmt, &tail);
    if (rc != SQLITE_OK) {
        sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement twice
    rc = sqlite3_step(stmt);
    rc = sqlite3_step(stmt);

    // Get the number of columns
    int col_count = sqlite3_column_count(stmt);

    // Access each column's type, name, and text
    for (int i = 0; i < col_count; i++) {
        sqlite3_column_type(stmt, i);
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function sqlite3_column_name with sqlite3_bind_parameter_name
        sqlite3_bind_parameter_name(stmt, i);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
        sqlite3_column_text(stmt, i);
        sqlite3_column_text(stmt, i);
        sqlite3_column_text(stmt, i);
        sqlite3_column_bytes(stmt, i);
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Close the database
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

    LLVMFuzzerTestOneInput_288(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
