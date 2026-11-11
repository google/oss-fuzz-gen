#include <sys/stat.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_335(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    
    // Open a new in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // If there's data, execute it as SQL
    if (size > 0) {
        char *errMsg = 0;
        
        // Ensure the data is null-terminated before passing it to sqlite3_exec
        char *sql = (char *)malloc(size + 1);
        if (sql == NULL) {
            sqlite3_close(db);
            return 0;
        }
        memcpy(sql, data, size);
        sql[size] = '\0';

        rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
        if (errMsg) {
            sqlite3_free(errMsg);
        }

        free(sql);
    }

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_open to sqlite3_open_v2
    char* ret_sqlite3_str_finish_einye = sqlite3_str_finish(NULL);
    if (ret_sqlite3_str_finish_einye == NULL){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_crmle = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_crmle < 0){
    	return 0;
    }
    char cmpiense[1024] = "iioar";
    sqlite3_uint64 ret_sqlite3_msize_iyibp = sqlite3_msize(cmpiense);
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_str_finish_einye) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!cmpiense) {
    	return 0;
    }
    int ret_sqlite3_open_v2_srlwh = sqlite3_open_v2(ret_sqlite3_str_finish_einye, &db, (int )ret_sqlite3_value_subtype_crmle, (const char *)cmpiense);
    if (ret_sqlite3_open_v2_srlwh < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int errcode = sqlite3_errcode(db);

    // Use the errcode in some way to avoid unused variable warning
    (void)errcode;

    // Close the database
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

    LLVMFuzzerTestOneInput_335(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
