#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
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
    rc = sqlite3_open(":memory:", &db);
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_get_table to sqlite3_uri_int64
    void* ret_sqlite3_malloc_zdwdg = sqlite3_malloc(size);
    if (ret_sqlite3_malloc_zdwdg == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_int64 ret_sqlite3_total_changes64_ozdbv = sqlite3_total_changes64(db);
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_zdwdg) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }
    sqlite3_int64 ret_sqlite3_uri_int64_audfg = sqlite3_uri_int64((const char *)ret_sqlite3_malloc_zdwdg, *result, ret_sqlite3_total_changes64_ozdbv);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_65(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
