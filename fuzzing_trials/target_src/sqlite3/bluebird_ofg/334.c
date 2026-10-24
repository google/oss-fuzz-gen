#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_334(const uint8_t *data, size_t size) {
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
    int ret_sqlite3_db_release_memory_mrudg = sqlite3_db_release_memory(db);
    if (ret_sqlite3_db_release_memory_mrudg < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_db_release_memory to sqlite3_open_v2
    char* ret_sqlite3_expanded_sql_gkqpl = sqlite3_expanded_sql(NULL);
    if (ret_sqlite3_expanded_sql_gkqpl == NULL){
    	return 0;
    }
    double ret_sqlite3_value_double_zlfty = sqlite3_value_double(NULL);
    if (ret_sqlite3_value_double_zlfty < 0){
    	return 0;
    }
    void* ret_sqlite3_malloc_ommkk = sqlite3_malloc(size);
    if (ret_sqlite3_malloc_ommkk == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_expanded_sql_gkqpl) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_malloc_ommkk) {
    	return 0;
    }
    int ret_sqlite3_open_v2_nptqz = sqlite3_open_v2(ret_sqlite3_expanded_sql_gkqpl, &db, (int )ret_sqlite3_value_double_zlfty, (const char *)ret_sqlite3_malloc_ommkk);
    if (ret_sqlite3_open_v2_nptqz < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    const char* ret_sqlite3_errmsg_utwkp = sqlite3_errmsg(db);
    if (ret_sqlite3_errmsg_utwkp == NULL){
    	return 0;
    }
    void* ret_sqlite3_malloc_vupbv = sqlite3_malloc(size);
    if (ret_sqlite3_malloc_vupbv == NULL){
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
    if (!ret_sqlite3_malloc_vupbv) {
    	return 0;
    }
    sqlite3_backup* ret_sqlite3_backup_init_rpltm = sqlite3_backup_init(db, errMsg, db, (const char *)ret_sqlite3_malloc_vupbv);
    if (ret_sqlite3_backup_init_rpltm == NULL){
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

    LLVMFuzzerTestOneInput_334(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
