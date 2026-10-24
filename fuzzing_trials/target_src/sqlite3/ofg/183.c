#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    // Initialize SQLite database connection
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure we have enough data to extract a 64-bit integer
    if (size < sizeof(sqlite3_int64)) {
        sqlite3_close(db);
        return 0;
    }

    // Extract a 64-bit integer from the input data
    sqlite3_int64 rowid = *(const sqlite3_int64 *)data;

    // Call the function-under-test
    sqlite3_set_last_insert_rowid(db, rowid);

    // Close the SQLite database connection
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

    LLVMFuzzerTestOneInput_183(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
