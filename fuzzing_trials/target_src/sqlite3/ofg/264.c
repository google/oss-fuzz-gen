#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_264(const uint8_t *data, size_t size) {
    sqlite3 *db_src = NULL;
    sqlite3 *db_dest = NULL;
    sqlite3_backup *backup = NULL;
    char *err_msg = NULL;

    if (sqlite3_open(":memory:", &db_src) != SQLITE_OK) {
        return 0;
    }

    if (sqlite3_open(":memory:", &db_dest) != SQLITE_OK) {
        sqlite3_close(db_src);
        return 0;
    }

    // Use the input data as SQL commands
    if (size > 0) {
        // Ensure the data is null-terminated
        char *sql = (char *)malloc(size + 1);
        if (sql == NULL) {
            sqlite3_close(db_src);
            sqlite3_close(db_dest);
            return 0;
        }
        memcpy(sql, data, size);
        sql[size] = '\0';

        // Execute the SQL command on the source database
        sqlite3_exec(db_src, sql, 0, 0, &err_msg);

        // Free the allocated memory
        free(sql);
    }

    // Create a backup object
    backup = sqlite3_backup_init(db_dest, "main", db_src, "main");
    if (backup == NULL) {
        sqlite3_close(db_src);
        sqlite3_close(db_dest);
        return 0;
    }

    // Perform some backup steps
    sqlite3_backup_step(backup, 5);

    // Call the function-under-test
    sqlite3_backup_finish(backup);

    // Clean up
    sqlite3_close(db_src);
    sqlite3_close(db_dest);

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

    LLVMFuzzerTestOneInput_264(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
