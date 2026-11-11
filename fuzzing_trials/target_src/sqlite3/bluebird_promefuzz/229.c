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
int LLVMFuzzerTestOneInput_229(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a new database connection
    rc = sqlite3_open(":memory:", &db);
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

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_exec to sqlite3_wal_checkpoint_v2
        sqlite3* ret_sqlite3_db_handle_zjqra = sqlite3_db_handle(NULL);
        if (ret_sqlite3_db_handle_zjqra == NULL){
        	return 0;
        }
        double ret_sqlite3_value_double_pvzed = sqlite3_value_double(NULL);
        if (ret_sqlite3_value_double_pvzed < 0){
        	return 0;
        }
        double ret_sqlite3_value_double_pqaqg = sqlite3_value_double(NULL);
        if (ret_sqlite3_value_double_pqaqg < 0){
        	return 0;
        }
        unsigned int ret_sqlite3_value_subtype_jjayy = sqlite3_value_subtype(NULL);
        if (ret_sqlite3_value_subtype_jjayy < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_db_handle_zjqra) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!errMsg) {
        	return 0;
        }
        int ret_sqlite3_wal_checkpoint_v2_fondz = sqlite3_wal_checkpoint_v2(ret_sqlite3_db_handle_zjqra, errMsg, (int )ret_sqlite3_value_double_pvzed, (int *)&ret_sqlite3_value_double_pqaqg, (int *)&ret_sqlite3_value_subtype_jjayy);
        if (ret_sqlite3_wal_checkpoint_v2_fondz < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        sqlite3_free(sql);
    }

    // Set authorizer callback
    sqlite3_set_authorizer(db, authorizer_callback, NULL);

    // Retrieve table column metadata
    const char *dataType, *collSeq;
    int notNull, primaryKey, autoinc;
    sqlite3_table_column_metadata(db, "main", "dummy_table", "dummy_column", &dataType, &collSeq, &notNull, &primaryKey, &autoinc);

    // Test control interface
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

    LLVMFuzzerTestOneInput_229(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
