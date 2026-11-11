#include <sys/stat.h>
#include "sqlite3.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    return 0;
}

int LLVMFuzzerTestOneInput_241(const unsigned char *Data, size_t Size) {
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

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_open to sqlite3_str_new using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    sqlite3_str* ret_sqlite3_str_new_zcjfv = sqlite3_str_new(db);
    if (ret_sqlite3_str_new_zcjfv == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK && errMsg != NULL) {
        sqlite3_free(errMsg);
    }

    // Backup operation
    rc = sqlite3_open(":memory:", &backupDb);
    if (rc == SQLITE_OK && backupDb != NULL) {
        const char qyhygyyf[1024] = "lgyab";
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of sqlite3_backup_init
        backup = sqlite3_backup_init(backupDb, "main", db, qyhygyyf);
        // End mutation: Producer.REPLACE_ARG_MUTATOR
        if (backup) {
            while ((rc = sqlite3_backup_step(backup, 5)) == SQLITE_OK) {
                // Do nothing, just step
            }
            sqlite3_backup_finish(backup);
        }

        // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_backup_init to sqlite3_errmsg using the plateau pool
        // Ensure dataflow is valid (i.e., non-null)
        if (!db) {
        	return 0;
        }
        const char* ret_sqlite3_errmsg_bsmzd = sqlite3_errmsg(db);
        if (ret_sqlite3_errmsg_bsmzd == NULL){
        	return 0;
        }
        // End mutation: Producer.SPLICE_MUTATOR
        
        sqlite3_close(backupDb);
    }

    // Deserialize operation

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_open to sqlite3_table_column_metadata using the plateau pool
    const char *dbName = "main";
    const char *tableName = "test";
    const char *columnName = "id";
    int pNotNull = 0, pPrimaryKey = 0, pAutoinc = 0;
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
    int ret_sqlite3_table_column_metadata_snxdd = sqlite3_table_column_metadata(db, dbName, tableName, columnName, &errMsg, &errMsg, &pNotNull, &pPrimaryKey, &pAutoinc);
    if (ret_sqlite3_table_column_metadata_snxdd < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_table_column_metadata to sqlite3_prepare16_v3 using the plateau pool
    int nByte = (int)Size;
    unsigned int prepFlags = 0;
    sqlite3_stmt *stmt = NULL;
    const char *pzTail = NULL;
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_prepare16_v3_wwirp = sqlite3_prepare16_v3(db, (const void *)db, nByte, prepFlags, &stmt, (const void **)&pzTail);
    if (ret_sqlite3_prepare16_v3_wwirp < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    unsigned char *serializedData;
    sqlite3_int64 serializedSize;
    serializedData = sqlite3_serialize(db, "main", &serializedSize, 0);
    if (serializedData) {
        rc = sqlite3_deserialize(db, "main", serializedData, serializedSize, serializedSize, 0);
        if (rc != SQLITE_OK) {
            sqlite3_free(serializedData);
        }
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_deserialize to sqlite3_strlike
        void* ret_sqlite3_malloc64_cmzlv = sqlite3_malloc64(0);
        if (ret_sqlite3_malloc64_cmzlv == NULL){
        	return 0;
        }
        double ret_sqlite3_value_double_uxlfl = sqlite3_value_double(NULL);
        if (ret_sqlite3_value_double_uxlfl < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_malloc64_cmzlv) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!serializedData) {
        	return 0;
        }
        int ret_sqlite3_strlike_nivrg = sqlite3_strlike((const char *)ret_sqlite3_malloc64_cmzlv, (const char *)serializedData, (unsigned int )ret_sqlite3_value_double_uxlfl);
        if (ret_sqlite3_strlike_nivrg < 0){
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

    LLVMFuzzerTestOneInput_241(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
