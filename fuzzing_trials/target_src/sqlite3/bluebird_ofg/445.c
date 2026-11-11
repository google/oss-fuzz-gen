#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_445(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a new in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if(rc) {
        sqlite3_close(db);
        return 0;
    }

    // Convert the fuzz input into a null-terminated string
    char *sql = (char *)malloc(size + 1);
    if (!sql) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the SQL command
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free allocated resources

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_get_table
    sqlite3* ret_sqlite3_db_handle_dhrfh = sqlite3_db_handle(NULL);
    if (ret_sqlite3_db_handle_dhrfh == NULL){
    	return 0;
    }
    double ret_sqlite3_value_double_bxyog = sqlite3_value_double(NULL);
    if (ret_sqlite3_value_double_bxyog < 0){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_dqwwt = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_dqwwt < 0){
    	return 0;
    }
    void* ret_sqlite3_malloc_anryr = sqlite3_malloc(1);
    if (ret_sqlite3_malloc_anryr == NULL){
    	return 0;
    }
    char **cmmhvpmn[1024] = {"hgdta", NULL};
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_db_handle_dhrfh) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_anryr) {
    	return 0;
    }
    int ret_sqlite3_get_table_egcfb = sqlite3_get_table(ret_sqlite3_db_handle_dhrfh, errMsg, cmmhvpmn, (int *)&ret_sqlite3_value_double_bxyog, (int *)&ret_sqlite3_value_subtype_dqwwt, (char **)&ret_sqlite3_malloc_anryr);
    if (ret_sqlite3_get_table_egcfb < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sqlite3_free(errMsg);
    free(sql);
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

    LLVMFuzzerTestOneInput_445(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
