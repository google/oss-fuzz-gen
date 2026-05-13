#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    char **result;
    int rows, columns;
    int rc;

    // Ensure data is null-terminated for use as a SQL query
    char *sqlQuery = (char *)malloc(size + 1);
    if (sqlQuery == NULL) {
        return 0;
    }
    memcpy(sqlQuery, data, size);
    sqlQuery[size] = '\0';

    // Open a temporary in-memory SQLite database
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    rc = sqlite3_open((const char *)"r", &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK) {
        free(sqlQuery);
        return 0;
    }

    // Execute the SQL query using sqlite3_get_table
    rc = sqlite3_get_table(db, sqlQuery, &result, &rows, &columns, &errMsg);

    // Clean up
    if (result) {
        sqlite3_free_table(result);
    }
    if (errMsg) {
        sqlite3_free(errMsg);
    }
    sqlite3_close(db);
    free(sqlQuery);

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

    LLVMFuzzerTestOneInput_2(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
