#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_265(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    int rc;

    // Initialize SQLite in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare a dummy file for SQL input
    write_dummy_file(Data, Size);

    // Prepare SQL statement
    rc = sqlite3_prepare_v2(db, (const char *)Data, Size, &stmt, &tail);
    if (rc != SQLITE_OK) {
        sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    // Execute the statement twice
    rc = sqlite3_step(stmt);
    rc = sqlite3_step(stmt);

    // Get the number of columns
    int col_count = sqlite3_column_count(stmt);

    // Access each column's type, name, and text
    for (int i = 0; i < col_count; i++) {
        sqlite3_column_type(stmt, i);
        sqlite3_column_name(stmt, i);
        sqlite3_column_text(stmt, i);
        sqlite3_column_text(stmt, i);

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sqlite3_column_text to sqlite3_prepare16_v3
        // Ensure dataflow is valid (i.e., non-null)
        if (!db) {
        	return 0;
        }
        int ret_sqlite3_error_offset_masem = sqlite3_error_offset(db);
        if (ret_sqlite3_error_offset_masem < 0){
        	return 0;
        }
        double ret_sqlite3_value_double_biltd = sqlite3_value_double(NULL);
        if (ret_sqlite3_value_double_biltd < 0){
        	return 0;
        }
        unsigned int ret_sqlite3_value_subtype_ksceh = sqlite3_value_subtype(NULL);
        if (ret_sqlite3_value_subtype_ksceh < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!stmt) {
        	return 0;
        }
        int ret_sqlite3_bind_parameter_count_jvbkz = sqlite3_bind_parameter_count(stmt);
        if (ret_sqlite3_bind_parameter_count_jvbkz < 0){
        	return 0;
        }
        sqlite3_vfs* ret_sqlite3_vfs_find_kapyu = sqlite3_vfs_find((const char *)Data);
        if (ret_sqlite3_vfs_find_kapyu == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!db) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!stmt) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!stmt) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_sqlite3_vfs_find_kapyu) {
        	return 0;
        }
        int ret_sqlite3_prepare16_v3_sjhce = sqlite3_prepare16_v3(db, (const void *)stmt, (int )ret_sqlite3_value_double_biltd, ret_sqlite3_value_subtype_ksceh, &stmt, (const void **)&ret_sqlite3_vfs_find_kapyu);
        if (ret_sqlite3_prepare16_v3_sjhce < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        sqlite3_column_text(stmt, i);
        sqlite3_column_bytes(stmt, i);
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

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

    LLVMFuzzerTestOneInput_265(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
