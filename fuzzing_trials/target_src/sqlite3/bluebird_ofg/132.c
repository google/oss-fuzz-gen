#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;

    // Open an in-memory database
    const char akuwchtr[1024] = "jrrhx";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    if (sqlite3_open(akuwchtr, &db) != SQLITE_OK) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        return 0;
    }

    // Ensure the data is null-terminated before passing it to sqlite3_exec
    char *sqlStatement = (char *)malloc(size + 1);
    if (sqlStatement == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sqlStatement, data, size);
    sqlStatement[size] = '\0'; // Null-terminate the input

    // Execute the data as an SQL statement
    if (size > 0) {
        sqlite3_exec(db, sqlStatement, 0, 0, &errMsg);
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_prepare_v2
        sqlite3* ret_sqlite3_db_handle_ynglf = sqlite3_db_handle(NULL);
        if (ret_sqlite3_db_handle_ynglf == NULL){
        	return 0;
        }
        unsigned int ret_sqlite3_value_subtype_qhepy = sqlite3_value_subtype(NULL);
        if (ret_sqlite3_value_subtype_qhepy < 0){
        	return 0;
        }
        char* ret_sqlite3_str_finish_fiobe = sqlite3_str_finish(NULL);
        if (ret_sqlite3_str_finish_fiobe == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_db_handle_ynglf) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_str_finish_fiobe) {
        	return 0;
        }
        int ret_sqlite3_prepare_v2_jlcwb = sqlite3_prepare_v2(ret_sqlite3_db_handle_ynglf, errMsg, (int )ret_sqlite3_value_subtype_qhepy, NULL, &ret_sqlite3_str_finish_fiobe);
        if (ret_sqlite3_prepare_v2_jlcwb < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Clean up
    if (errMsg) {
        sqlite3_free(errMsg);
    }
    sqlite3_close(db);
    free(sqlStatement);

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

    LLVMFuzzerTestOneInput_132(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
