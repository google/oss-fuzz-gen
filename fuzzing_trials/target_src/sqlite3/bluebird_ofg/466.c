#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_466(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_open to sqlite3_prepare16_v2
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_error_offset_wygxz = sqlite3_error_offset(db);
    if (ret_sqlite3_error_offset_wygxz < 0){
    	return 0;
    }
    double ret_sqlite3_value_double_hnazw = sqlite3_value_double(NULL);
    if (ret_sqlite3_value_double_hnazw < 0){
    	return 0;
    }
    sqlite3_str* ret_sqlite3_str_new_qsniy = sqlite3_str_new(NULL);
    if (ret_sqlite3_str_new_qsniy == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_str_new_qsniy) {
    	return 0;
    }
    int ret_sqlite3_prepare16_v2_klcfr = sqlite3_prepare16_v2(db, (const void *)db, (int )ret_sqlite3_value_double_hnazw, NULL, (const void **)&ret_sqlite3_str_new_qsniy);
    if (ret_sqlite3_prepare16_v2_klcfr < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char *errMsg = NULL;
    sqlite3_exec(db, query, 0, 0, &errMsg);

    // Clean up
    if (errMsg) {
        sqlite3_free(errMsg);
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_get_table
    sqlite3* ret_sqlite3_db_handle_amcoc = sqlite3_db_handle(NULL);
    if (ret_sqlite3_db_handle_amcoc == NULL){
    	return 0;
    }
    double ret_sqlite3_value_double_twoyz = sqlite3_value_double(NULL);
    if (ret_sqlite3_value_double_twoyz < 0){
    	return 0;
    }
    unsigned int ret_sqlite3_value_subtype_zcjdg = sqlite3_value_subtype(NULL);
    if (ret_sqlite3_value_subtype_zcjdg < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errMsg) {
    	return 0;
    }
    sqlite3_uint64 ret_sqlite3_msize_yrsxu = sqlite3_msize((void *)errMsg);
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_db_handle_amcoc) {
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
    int ret_sqlite3_get_table_jjquz = sqlite3_get_table(ret_sqlite3_db_handle_amcoc, errMsg, (char ***)"w", (int *)&ret_sqlite3_value_double_twoyz, (int *)&ret_sqlite3_value_subtype_zcjdg, errMsg);
    if (ret_sqlite3_get_table_jjquz < 0){
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

    LLVMFuzzerTestOneInput_466(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
