#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_206(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;

    // Open an in-memory database
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    if (sqlite3_open((const char *)"r", &db) != SQLITE_OK) {
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
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_create_filename
        char* ret_sqlite3_expanded_sql_zavsu = sqlite3_expanded_sql(NULL);
        if (ret_sqlite3_expanded_sql_zavsu == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        sqlite3_uint64 ret_sqlite3_msize_jffrc = sqlite3_msize((void *)errMsg);
        double ret_sqlite3_value_double_wllqa = sqlite3_value_double(NULL);
        if (ret_sqlite3_value_double_wllqa < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        sqlite3_uint64 ret_sqlite3_msize_isipg = sqlite3_msize((void *)errMsg);
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_expanded_sql_zavsu) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        if (!*errMsg) {
        	return 0;
        }
        sqlite3_filename ret_sqlite3_create_filename_fpinc = sqlite3_create_filename(ret_sqlite3_expanded_sql_zavsu, errMsg, errMsg, (int )ret_sqlite3_value_double_wllqa, errMsg);
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

    LLVMFuzzerTestOneInput_206(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
