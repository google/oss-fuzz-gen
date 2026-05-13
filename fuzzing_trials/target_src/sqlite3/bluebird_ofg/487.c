#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Fuzzing function
int LLVMFuzzerTestOneInput_487(const uint8_t *data, size_t size) {
    // Convert input data to a null-terminated string
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        return 0; // Fail gracefully on allocation failure
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Initialize an SQLite database in memory
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        free(sql);
        return 0;
    }

    // Execute the SQL statement

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_open to sqlite3_open_v2
    void* ret_sqlite3_malloc_nbhhk = sqlite3_malloc(0);
    if (ret_sqlite3_malloc_nbhhk == NULL){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_yklcd = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_yklcd < 0){
    	return 0;
    }
    void* ret_sqlite3_malloc_cazzg = sqlite3_malloc(1);
    if (ret_sqlite3_malloc_cazzg == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_nbhhk) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_cazzg) {
    	return 0;
    }
    int ret_sqlite3_open_v2_eoxze = sqlite3_open_v2((const char *)ret_sqlite3_malloc_nbhhk, &db, (int )ret_sqlite3_value_subtype_yklcd, (const char *)ret_sqlite3_malloc_cazzg);
    if (ret_sqlite3_open_v2_eoxze < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char *errMsg = 0;
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free resources
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

    LLVMFuzzerTestOneInput_487(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
