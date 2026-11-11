#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_mutex *mutex = NULL;
    int rc;

    // Open a database connection in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure that the database connection is valid
    if (db != NULL) {
        // Call the function-under-test
        mutex = sqlite3_db_mutex(db);

        // Use the mutex in some way to prevent compiler optimizations
        if (mutex != NULL) {
            sqlite3_mutex_enter(mutex);
            sqlite3_mutex_leave(mutex);
        }

        // Close the database connection
        sqlite3_close(db);
    }

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

    LLVMFuzzerTestOneInput_74(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
