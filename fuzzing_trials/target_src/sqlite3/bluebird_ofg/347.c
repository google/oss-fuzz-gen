#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

// Dummy busy handler function
int busy_handler_347(void *data, int count) {
    return 0; // Always return 0 to indicate that the operation should not be retried
}

int LLVMFuzzerTestOneInput_347(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    char *errMsg = 0;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Set the busy handler for the database
    sqlite3_busy_handler(db, busy_handler_347, NULL);

    // Ensure the input data is null-terminated for use as a SQL statement
    char *sql = (char *)malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    // Execute the SQL statement
    sqlite3_exec(db, sql, 0, 0, &errMsg);

    // Free allocated resources

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_exec to sqlite3_prepare_v2 using the plateau pool
    sqlite3_stmt *stmt;
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
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
    int ret_sqlite3_prepare_v2_edzcv = sqlite3_prepare_v2(db, errMsg, -1, &stmt, &errMsg);
    if (ret_sqlite3_prepare_v2_edzcv < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
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

    LLVMFuzzerTestOneInput_347(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
