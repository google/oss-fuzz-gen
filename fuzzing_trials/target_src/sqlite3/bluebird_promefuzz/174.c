#include <sys/stat.h>
#include "sqlite3.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_174(const unsigned char *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure null-terminated SQL input
    char *sql = (char *)malloc(Size + 1);
    if (!sql) {
        return 0;
    }
    memcpy(sql, Data, Size);
    sql[Size] = '\0';

    // Initialize variables
    sqlite3 *db = NULL;
    sqlite3 *backupDb = NULL;
    sqlite3_backup *backup = NULL;
    char *errMsg = NULL;
    int rc;

    // Prepare filename
    char filename[256];
    snprintf(filename, sizeof(filename), "./dummy_file_%zu", Size);

    // Open a database connection
    const char amvzptky[1024] = "dxxvg";
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of sqlite3_open
    rc = sqlite3_open(amvzptky, &db);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (rc != SQLITE_OK || db == NULL) {
        free(sql);
        return 0;
    }

    // Execute some SQL
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK && errMsg != NULL) {
        sqlite3_free(errMsg);
    }

    // Backup operation
    rc = sqlite3_open(":memory:", &backupDb);
    if (rc == SQLITE_OK && backupDb != NULL) {
        backup = sqlite3_backup_init(backupDb, "main", db, "main");
        if (backup) {
            while ((rc = sqlite3_backup_step(backup, 5)) == SQLITE_OK) {
                // Do nothing, just step
            }
            sqlite3_backup_finish(backup);
        
            // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_backup_finish to sqlite3_blob_read
            // Ensure dataflow is valid (i.e., non-null)
            if (!backup) {
            	return 0;
            }
            int ret_sqlite3_blob_read_kqeue = sqlite3_blob_read(NULL, (void *)backup, -1, 1);
            if (ret_sqlite3_blob_read_kqeue < 0){
            	return 0;
            }
            // End mutation: Producer.APPEND_MUTATOR
            

            // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_blob_read to sqlite3_blob_open
            // Ensure dataflow is valid (i.e., non-null)
            if (!backupDb) {
            	return 0;
            }
            const void* ret_sqlite3_errmsg16_dtfxl = sqlite3_errmsg16(backupDb);
            if (ret_sqlite3_errmsg16_dtfxl == NULL){
            	return 0;
            }
            char* ret_sqlite3_str_value_nqmkx = sqlite3_str_value(NULL);
            if (ret_sqlite3_str_value_nqmkx == NULL){
            	return 0;
            }
            void* ret_sqlite3_malloc_wbcqa = sqlite3_malloc(0);
            if (ret_sqlite3_malloc_wbcqa == NULL){
            	return 0;
            }
            double ret_sqlite3_value_double_iylqg = sqlite3_value_double(NULL);
            if (ret_sqlite3_value_double_iylqg < 0){
            	return 0;
            }
            int ret_sqlite3_blob_bytes_bugue = sqlite3_blob_bytes(backup);
            if (ret_sqlite3_blob_bytes_bugue < 0){
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!backupDb) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!backup) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!ret_sqlite3_str_value_nqmkx) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!ret_sqlite3_malloc_wbcqa) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!backup) {
            	return 0;
            }
            int ret_sqlite3_blob_open_bkjol = sqlite3_blob_open(backupDb, backup, ret_sqlite3_str_value_nqmkx, (const char *)ret_sqlite3_malloc_wbcqa, 0, (int )ret_sqlite3_value_double_iylqg, &backup);
            if (ret_sqlite3_blob_open_bkjol < 0){
            	return 0;
            }
            // End mutation: Producer.APPEND_MUTATOR
            
}
        sqlite3_close(backupDb);
    }

    // Deserialize operation
    unsigned char *serializedData;
    sqlite3_int64 serializedSize;
    serializedData = sqlite3_serialize(db, "main", &serializedSize, 0);
    if (serializedData) {
        rc = sqlite3_deserialize(db, "main", serializedData, serializedSize, serializedSize, 0);
        if (rc != SQLITE_OK) {
            sqlite3_free(serializedData);
        }
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_deserialize to sqlite3_uri_parameter
        char* ret_sqlite3_str_value_tcxcj = sqlite3_str_value(NULL);
        if (ret_sqlite3_str_value_tcxcj == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_str_value_tcxcj) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!serializedData) {
        	return 0;
        }
        const char* ret_sqlite3_uri_parameter_kqnez = sqlite3_uri_parameter(ret_sqlite3_str_value_tcxcj, (const char *)serializedData);
        if (ret_sqlite3_uri_parameter_kqnez == NULL){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Close the database connection
    sqlite3_close(db);

    // Free allocated memory
    free(sql);

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

    LLVMFuzzerTestOneInput_174(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
