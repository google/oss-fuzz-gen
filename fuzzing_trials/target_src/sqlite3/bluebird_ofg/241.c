#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_241(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    const char *sql;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure the data is null-terminated for SQLite
    char *sql_data = (char *)malloc(size + 1);
    if (sql_data == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql_data, data, size);
    sql_data[size] = '\0';

    // Prepare the SQL statement
    rc = sqlite3_prepare_v2(db, sql_data, -1, &stmt, &sql);
    if (rc == SQLITE_OK) {
        // Call the function-under-test
        int readonly = sqlite3_stmt_readonly(stmt);

        // Finalize the statement
        sqlite3_finalize(stmt);
    }

    // Clean up
    free(sql_data);
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

    LLVMFuzzerTestOneInput_241(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
