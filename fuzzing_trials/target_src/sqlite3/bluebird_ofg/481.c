#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <string.h> // Include for memcpy and malloc

int LLVMFuzzerTestOneInput_481(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    
    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Allocate a new buffer for the SQL statement with an extra byte for the null terminator

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_open to sqlite3_prepare16_v2
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_error_offset_kqxmj = sqlite3_error_offset(db);
    if (ret_sqlite3_error_offset_kqxmj < 0){
    	return 0;
    }
    double ret_sqlite3_value_double_yukaz = sqlite3_value_double(NULL);
    if (ret_sqlite3_value_double_yukaz < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_str* ret_sqlite3_str_new_rlfgr = sqlite3_str_new(db);
    if (ret_sqlite3_str_new_rlfgr == NULL){
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
    if (!ret_sqlite3_str_new_rlfgr) {
    	return 0;
    }
    int ret_sqlite3_prepare16_v2_vadxm = sqlite3_prepare16_v2(db, (const void *)db, (int )ret_sqlite3_value_double_yukaz, NULL, (const void **)&ret_sqlite3_str_new_rlfgr);
    if (ret_sqlite3_prepare16_v2_vadxm < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }

    // Copy the input data to the new buffer and null-terminate it
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the fuzz data as an SQL statement
    char *errMsg = NULL;
    sqlite3_exec(db, sql, NULL, NULL, &errMsg);
    if (errMsg) {
        sqlite3_free(errMsg);
    }

    // Call the function-under-test
    sqlite3_int64 changes = sqlite3_total_changes64(db);

    // Free the allocated buffer
    free(sql);

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

    LLVMFuzzerTestOneInput_481(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
