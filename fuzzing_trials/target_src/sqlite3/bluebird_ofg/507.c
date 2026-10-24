#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_507(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_blob_open
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_int64 ret_sqlite3_total_changes64_mjpgs = sqlite3_total_changes64(db);
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_uint64 ret_sqlite3_msize_wbhgd = sqlite3_msize((void *)db);
    void* ret_sqlite3_malloc64_wwbrp = sqlite3_malloc64(0);
    if (ret_sqlite3_malloc64_wwbrp == NULL){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_oztbl = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_oztbl < 0){
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
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc64_wwbrp) {
    	return 0;
    }
    int ret_sqlite3_blob_open_vjeua = sqlite3_blob_open(db, errMsg, db, (const char *)ret_sqlite3_malloc64_wwbrp, 0, (int )ret_sqlite3_value_subtype_oztbl, NULL);
    if (ret_sqlite3_blob_open_vjeua < 0){
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

    LLVMFuzzerTestOneInput_507(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
