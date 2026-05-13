#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <string.h> // Include for memcpy and malloc

int LLVMFuzzerTestOneInput_391(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    
    // Open an in-memory database
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    rc = sqlite3_open((const char *)"w", &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Allocate a new buffer for the SQL statement with an extra byte for the null terminator

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_open to sqlite3_open16
    sqlite3_vfs* ret_sqlite3_vfs_find_aorsc = sqlite3_vfs_find((const char *)data);
    if (ret_sqlite3_vfs_find_aorsc == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sqlite3_vfs_find_aorsc) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_open16_zihhm = sqlite3_open16((const void *)ret_sqlite3_vfs_find_aorsc, &db);
    if (ret_sqlite3_open16_zihhm < 0){
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

    LLVMFuzzerTestOneInput_391(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
