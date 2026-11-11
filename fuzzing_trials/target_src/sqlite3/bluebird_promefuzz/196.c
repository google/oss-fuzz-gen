#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Dummy authorizer callback function
static int authorizer_callback(void *pUserData, int action, const char *details1, const char *details2, const char *details3, const char *details4) {
    // Always allow the action
    return SQLITE_OK;
}

// Dummy callback function for sqlite3_exec
static int exec_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

// Fuzzing entry point
int LLVMFuzzerTestOneInput_196(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a new database connection
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    rc = sqlite3_open((const char *)"w", &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc) {
        return 0;
    }

    // Prepare SQL statement from fuzz data
    char *sql = sqlite3_malloc(Size + 1);
    if (sql) {
        memcpy(sql, Data, Size);
        sql[Size] = '\0';

        // Execute SQL statement
        sqlite3_exec(db, sql, exec_callback, 0, &errMsg);

        // Free error message if allocated
        if (errMsg) {
            sqlite3_free(errMsg);
        }

        // Free SQL statement
        sqlite3_free(sql);
    }

    // Set authorizer callback
    sqlite3_set_authorizer(db, authorizer_callback, NULL);

    // Retrieve table column metadata
    const char *dataType, *collSeq;
    int notNull, primaryKey, autoinc;
    sqlite3_table_column_metadata(db, "main", "dummy_table", "dummy_column", &dataType, &collSeq, &notNull, &primaryKey, &autoinc);

    // Test control interface

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_table_column_metadata to sqlite3_prepare_v2 using the plateau pool
    sqlite3_stmt *stmt = NULL;
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sql) {
    	return 0;
    }
    int ret_sqlite3_prepare_v2_cjjhg = sqlite3_prepare_v2(db, "SELECT * FROM test;", -1, &stmt, (const char **)&sql);
    if (ret_sqlite3_prepare_v2_cjjhg < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    sqlite3_test_control(SQLITE_TESTCTRL_FIRST);

    // Allocate memory using sqlite3_malloc
    void *memory = sqlite3_malloc(100);
    if (memory) {
        memset(memory, 0, 100);
        sqlite3_free(memory);
    }

    // Close the database connection
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

    LLVMFuzzerTestOneInput_196(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
