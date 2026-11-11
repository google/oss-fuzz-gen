#include <sys/stat.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput_243(const uint8_t *data, size_t size) {
    sqlite3 *src_db = NULL;
    sqlite3 *dest_db = NULL;
    sqlite3_backup *backup;
    char *src_db_name = "source.db";
    char *dest_db_name = "destination.db";
    char *err_msg = NULL;

    // Initialize source and destination databases
    if (sqlite3_open(":memory:", &src_db) != SQLITE_OK) {
        return 0;
    }
    if (sqlite3_open(":memory:", &dest_db) != SQLITE_OK) {
        sqlite3_close(src_db);
        return 0;
    }

    // Create a table in the source database
    const char *create_table_sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, data BLOB);";
    if (sqlite3_exec(src_db, create_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_close(src_db);
        sqlite3_close(dest_db);
        return 0;
    }

    // Insert the fuzz data into the source database
    sqlite3_stmt *stmt;
    const char *insert_sql = "INSERT INTO test (data) VALUES (?);";
    if (sqlite3_prepare_v2(src_db, insert_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Initialize the backup process
    backup = sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (backup) {
        // Perform the backup step
        sqlite3_backup_step(backup, -1);
        sqlite3_backup_finish(backup);
    }

    // Cleanup
    sqlite3_close(src_db);
    sqlite3_close(dest_db);

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

    LLVMFuzzerTestOneInput_243(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
