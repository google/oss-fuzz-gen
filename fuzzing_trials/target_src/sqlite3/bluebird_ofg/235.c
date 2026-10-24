#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_235(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql;
    const char *decl_type;

    // Ensure the input data is null-terminated for SQL statement
    char *sql_statement = (char *)malloc(size + 1);
    if (!sql_statement) {
        return 0;
    }
    memcpy(sql_statement, data, size);
    sql_statement[size] = '\0';

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        free(sql_statement);
        return 0;
    }

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_statement, -1, &stmt, &sql);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        free(sql_statement);
        return 0;
    }

    // Fuzz the sqlite3_column_decltype function with various column indices
    for (int i = 0; i < sqlite3_column_count(stmt); i++) {
        decl_type = sqlite3_column_decltype(stmt, i);
        // Optionally print or log the decl_type for debugging
        if (decl_type) {
            printf("Column %d: %s\n", i, decl_type);
        }
    }

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    free(sql_statement);

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

    LLVMFuzzerTestOneInput_235(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
