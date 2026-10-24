#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>

static int progress_callback(void *unused) {
    return 0; // Continue execution
}

int LLVMFuzzerTestOneInput_274(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    // Initialize SQLite
    if (sqlite3_initialize() != SQLITE_OK) {
        return 0;
    }

    // Open a database connection
    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (sqlite3_open_v2("./dummy_file", &db, flags, NULL) != SQLITE_OK) {
        sqlite3_shutdown();
        return 0;
    }

    // Set a progress handler
    sqlite3_progress_handler(db, 1000, progress_callback, NULL);

    // Set and query limits
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, (int)Data[0]);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, -1); // Query current limit
    sqlite3_hard_heap_limit64((sqlite3_int64)Size);

    // Set another limit
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, (int)Data[0]);

    // Configure database connection
    sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0);

    // Close the database connection
    sqlite3_close(db);

    // Shutdown SQLite
    sqlite3_shutdown();

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

    LLVMFuzzerTestOneInput_274(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
