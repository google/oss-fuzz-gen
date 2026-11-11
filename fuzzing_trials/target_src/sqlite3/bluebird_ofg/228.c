#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_deserialize
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_db_release_memory_karpc = sqlite3_db_release_memory(db);
    if (ret_sqlite3_db_release_memory_karpc < 0){
    	return 0;
    }
    void* ret_sqlite3_malloc_rzyyy = sqlite3_malloc(-1);
    if (ret_sqlite3_malloc_rzyyy == NULL){
    	return 0;
    }
    sqlite3_int64 ret_sqlite3_changes64_yqhan = sqlite3_changes64(NULL);
    sqlite3_int64 ret_sqlite3_memory_highwater_zoquv = sqlite3_memory_highwater(-1);
    unsigned int ret_sqlite3_value_subtype_taqma = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_taqma < 0){
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
    if (!ret_sqlite3_malloc_rzyyy) {
    	return 0;
    }
    int ret_sqlite3_deserialize_bxwvs = sqlite3_deserialize(db, errMsg, (unsigned char *)ret_sqlite3_malloc_rzyyy, ret_sqlite3_changes64_yqhan, ret_sqlite3_memory_highwater_zoquv, ret_sqlite3_value_subtype_taqma);
    if (ret_sqlite3_deserialize_bxwvs < 0){
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

    LLVMFuzzerTestOneInput_228(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
