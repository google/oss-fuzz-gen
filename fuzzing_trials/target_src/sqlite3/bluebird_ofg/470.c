#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Ensure that the function is defined with C linkage
int LLVMFuzzerTestOneInput_470(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a sqlite3 database
    if (size == 0) {
        return 0;
    }

    sqlite3 *db;
    char *errMsg = 0;

    // Open a new in-memory database
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    int rc = sqlite3_open((const char *)"w", &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Convert input data to a null-terminated string

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_open to sqlite3_open16
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_extended_errcode_nvear = sqlite3_extended_errcode(db);
    if (ret_sqlite3_extended_errcode_nvear < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_extended_errcode to sqlite3_open16
    sqlite3_vfs* ret_sqlite3_vfs_find_vsliy = sqlite3_vfs_find(NULL);
    if (ret_sqlite3_vfs_find_vsliy == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_vfs_find_vsliy) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_open16_eqkyk = sqlite3_open16((const void *)ret_sqlite3_vfs_find_vsliy, &db);
    if (ret_sqlite3_open16_eqkyk < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int ret_sqlite3_open16_rjrpy = sqlite3_open16((const void *)db, &db);
    if (ret_sqlite3_open16_rjrpy < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the SQL statement
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free the error message if it was allocated
    if (errMsg) {
        sqlite3_free(errMsg);
    }

    // Free the allocated SQL string
    free(sql);

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

    LLVMFuzzerTestOneInput_470(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
