#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Fuzzing function
int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Convert input data to a null-terminated string
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        return 0; // Fail gracefully on allocation failure
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Initialize an SQLite database in memory
    sqlite3 *db;
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    if (sqlite3_open((const char *)"w", &db) != SQLITE_OK) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        free(sql);
        return 0;
    }

    // Execute the SQL statement
    char *errMsg = 0;
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free resources

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_strlike
    void* ret_sqlite3_malloc_sembz = sqlite3_malloc(-1);
    if (ret_sqlite3_malloc_sembz == NULL){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_rlivc = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_rlivc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_sembz) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    int ret_sqlite3_strlike_fnrdy = sqlite3_strlike((const char *)ret_sqlite3_malloc_sembz, errMsg, ret_sqlite3_value_subtype_rlivc);
    if (ret_sqlite3_strlike_fnrdy < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sqlite3_free(errMsg);
    sqlite3_close(db);
    free(sql);

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

    LLVMFuzzerTestOneInput_179(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
