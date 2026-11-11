#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to safely use as a SQL query
    char *query = (char *)malloc(size + 1);
    if (query == NULL) {
        return 0;
    }
    memcpy(query, data, size);
    query[size] = '\0';

    // Open an in-memory SQLite database
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_uri_int64
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_uint64 ret_sqlite3_msize_pavvb = sqlite3_msize((void *)db);
    sqlite3_int64 ret_sqlite3_hard_heap_limit64_yswlr = sqlite3_hard_heap_limit64(0);
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    sqlite3_int64 ret_sqlite3_uri_int64_wcumd = sqlite3_uri_int64(db, errMsg, ret_sqlite3_hard_heap_limit64_yswlr);
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

    LLVMFuzzerTestOneInput_30(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
