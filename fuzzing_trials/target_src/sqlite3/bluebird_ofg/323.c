#include <sys/stat.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Callback function for sqlite3_exec
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    (void)NotUsed;
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    return 0;
}

int LLVMFuzzerTestOneInput_323(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Initialize database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Convert fuzz data to a null-terminated string
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute SQL statement
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errMsg);
    }

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_blob_open
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_int64 ret_sqlite3_total_changes64_cajfj = sqlite3_total_changes64(db);
    void* ret_sqlite3_malloc_ywngj = sqlite3_malloc(64);
    if (ret_sqlite3_malloc_ywngj == NULL){
    	return 0;
    }
    void* ret_sqlite3_malloc_ncavg = sqlite3_malloc(-1);
    if (ret_sqlite3_malloc_ncavg == NULL){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_dyanc = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_dyanc < 0){
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
    if (!ret_sqlite3_malloc_ywngj) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_ncavg) {
    	return 0;
    }
    int ret_sqlite3_blob_open_mofck = sqlite3_blob_open(db, errMsg, (const char *)ret_sqlite3_malloc_ywngj, (const char *)ret_sqlite3_malloc_ncavg, 0, (int )ret_sqlite3_value_subtype_dyanc, NULL);
    if (ret_sqlite3_blob_open_mofck < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_323(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
