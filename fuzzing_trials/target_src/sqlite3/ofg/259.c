#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_259(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    sqlite3 *db = NULL;
    int result = 0;
    int flags = 0;

    // Open a new in-memory SQLite database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // If the database can't be opened, exit early
    }

    // Ensure the size is at least 1 to avoid accessing out-of-bounds
    if (size > 0) {
        // Use the first byte of data to determine the flags value
        flags = data[0];
    }

    // Call the function-under-test
    result = sqlite3_extended_result_codes(db, flags);

    // Clean up and close the database
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

    LLVMFuzzerTestOneInput_259(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
