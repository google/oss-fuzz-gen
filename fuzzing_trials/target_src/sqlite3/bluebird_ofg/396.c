#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_396(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to safely use as a SQL query
    char *query = (char *)malloc(size + 1);
    if (query == NULL) {
        return 0;
    }
    memcpy(query, data, size);
    query[size] = '\0';

    // Open an in-memory SQLite database
    sqlite3 *db;
    const char sicnesjp[1024] = "wnqtz";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    if (sqlite3_open(sicnesjp, &db) != SQLITE_OK) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        free(query);
        return 0;
    }

    // Execute the query
    char *errMsg = NULL;
    sqlite3_exec(db, query, 0, 0, &errMsg);

    // Clean up
    if (errMsg) {
        sqlite3_free(errMsg);
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_backup_init
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_str* ret_sqlite3_str_new_kqfbs = sqlite3_str_new(db);
    if (ret_sqlite3_str_new_kqfbs == NULL){
    	return 0;
    }
    sqlite3* ret_sqlite3_db_handle_ipmbx = sqlite3_db_handle(NULL);
    if (ret_sqlite3_db_handle_ipmbx == NULL){
    	return 0;
    }
    void* ret_sqlite3_malloc_trvjf = sqlite3_malloc(-1);
    if (ret_sqlite3_malloc_trvjf == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_db_handle_ipmbx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_trvjf) {
    	return 0;
    }
    sqlite3_backup* ret_sqlite3_backup_init_hnpno = sqlite3_backup_init(db, errMsg, ret_sqlite3_db_handle_ipmbx, (const char *)ret_sqlite3_malloc_trvjf);
    if (ret_sqlite3_backup_init_hnpno == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sqlite3_close(db);
    free(query);

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

    LLVMFuzzerTestOneInput_396(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
