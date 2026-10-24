#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Fuzzing function
int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
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
    char *errMsg = 0;
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free resources

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_create_filename
    void* ret_sqlite3_malloc_oahlr = sqlite3_malloc(size);
    if (ret_sqlite3_malloc_oahlr == NULL){
    	return 0;
    }
    char* ret_sqlite3_str_finish_tscxe = sqlite3_str_finish(NULL);
    if (ret_sqlite3_str_finish_tscxe == NULL){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_pozdy = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_pozdy < 0){
    	return 0;
    }
    void* ret_sqlite3_user_data_teuyq = sqlite3_user_data(NULL);
    if (ret_sqlite3_user_data_teuyq == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_oahlr) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_str_finish_tscxe) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_user_data_teuyq) {
    	return 0;
    }
    sqlite3_filename ret_sqlite3_create_filename_wqqfp = sqlite3_create_filename((const char *)ret_sqlite3_malloc_oahlr, errMsg, ret_sqlite3_str_finish_tscxe, (int )ret_sqlite3_value_subtype_pozdy, (const char **)&ret_sqlite3_user_data_teuyq);
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

    LLVMFuzzerTestOneInput_83(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
