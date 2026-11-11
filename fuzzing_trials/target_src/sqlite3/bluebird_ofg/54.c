#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <stdio.h> // Include stdio.h for snprintf

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    sqlite3 *srcDb = NULL;
    sqlite3 *destDb = NULL;
    sqlite3_backup *backup = NULL;
    int nPage = 1; // Number of pages to copy in each step

    // Initialize SQLite databases
    if (sqlite3_open(":memory:", &srcDb) != SQLITE_OK) {
        return 0;
    }
    if (sqlite3_open(":memory:", &destDb) != SQLITE_OK) {
        sqlite3_close(srcDb);
        return 0;
    }

    // Create a table in the source database
    sqlite3_exec(srcDb, "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);", NULL, NULL, NULL);

    // Insert data into the source database
    if (size > 0) {
        char *sql = (char *)malloc(size + 100);
        snprintf(sql, size + 100, "INSERT INTO test (value) VALUES ('%.*s');", (int)size, data);
        sqlite3_exec(srcDb, sql, NULL, NULL, NULL);
        free(sql);
    }

    // Initialize the backup process
    backup = sqlite3_backup_init(destDb, "main", srcDb, "main");
    if (backup == NULL) {
        sqlite3_close(srcDb);
        sqlite3_close(destDb);
        return 0;
    }

    // Perform the backup step
    sqlite3_backup_step(backup, nPage);

    // Finish the backup process
    sqlite3_backup_finish(backup);

    // Close the databases
    sqlite3_close(srcDb);
    sqlite3_close(destDb);

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

    LLVMFuzzerTestOneInput_54(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
