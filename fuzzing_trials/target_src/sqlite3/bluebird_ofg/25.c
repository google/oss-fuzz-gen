#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize SQLite
    if (sqlite3_initialize() != SQLITE_OK) {
        return 0;
    }

    // Open an in-memory database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        sqlite3_shutdown();
        return 0;
    }

    // Ensure the input data is null-terminated for safe use as a string

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_open to sqlite3_prepare_v2 using the plateau pool
    sqlite3_stmt *stmt;
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    const char *ncwkjifw[1024] = {"bnquc", NULL};
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 4 of sqlite3_prepare_v2
    int ret_sqlite3_prepare_v2_jgrxx = sqlite3_prepare_v2(db, "SELECT ?;", -1, &stmt, ncwkjifw);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (ret_sqlite3_prepare_v2_jgrxx < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        sqlite3_close(db);
        sqlite3_shutdown();
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the SQL statement
    char *errMsg = 0;
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Cleanup
    sqlite3_free(errMsg);
    free(sql);
    sqlite3_close(db);
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

    LLVMFuzzerTestOneInput_25(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
