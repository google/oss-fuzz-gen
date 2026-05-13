#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int checkpoint_threshold;

    // Initialize SQLite database in memory
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Ensure data size is sufficient to extract an integer for checkpoint threshold
    if (size < sizeof(int)) {
        sqlite3_close(db);
        return 0;
    }

    // Extract an integer from the input data for checkpoint threshold
    checkpoint_threshold = *((int*)data);

    // Call the function-under-test
    sqlite3_wal_autocheckpoint(db, checkpoint_threshold);

    // Close the SQLite database
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

    LLVMFuzzerTestOneInput_168(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
