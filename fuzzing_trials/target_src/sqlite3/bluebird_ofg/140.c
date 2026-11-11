#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_stricmp
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_create_module
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    const void* ret_sqlite3_errmsg16_bxnow = sqlite3_errmsg16(db);
    if (ret_sqlite3_errmsg16_bxnow == NULL){
    	return 0;
    }
    sqlite3_vfs* ret_sqlite3_vfs_find_mapjv = sqlite3_vfs_find(NULL);
    if (ret_sqlite3_vfs_find_mapjv == NULL){
    	return 0;
    }
    const sqlite3_module wrcyafbw;
    memset(&wrcyafbw, 0, sizeof(wrcyafbw));
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_vfs_find_mapjv) {
    	return 0;
    }
    int ret_sqlite3_create_module_xrlue = sqlite3_create_module(db, errMsg, &wrcyafbw, (void *)ret_sqlite3_vfs_find_mapjv);
    if (ret_sqlite3_create_module_xrlue < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int ret_sqlite3_stricmp_ahuyy = sqlite3_stricmp((const char *)"r", errMsg);
    if (ret_sqlite3_stricmp_ahuyy < 0){
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

    LLVMFuzzerTestOneInput_140(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
