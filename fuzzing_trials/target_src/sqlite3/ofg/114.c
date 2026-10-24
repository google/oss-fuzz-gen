#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Initialize SQLite database
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db); // Open an in-memory database
    if (rc != SQLITE_OK) {
        return 0; // If opening the database failed, exit early
    }

    // Ensure the data is null-terminated for use as a string
    char *zDbName = (char *)malloc(size + 1);
    if (zDbName == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(zDbName, data, size);
    zDbName[size] = '\0';

    // Call the function-under-test
    const char *filename = sqlite3_db_filename(db, zDbName);

    // Clean up
    free(zDbName);
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

    LLVMFuzzerTestOneInput_114(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
