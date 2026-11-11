#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"

// Define a simple callback function to use with sqlite3_profile
void profile_callback(void *arg, const char *sql, sqlite3_uint64 time) {
    // Do nothing, just a placeholder for the callback
}

int LLVMFuzzerTestOneInput_447(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // Return if the database couldn't be opened
    }

    // Use the first part of the data as a pointer to pass to the profile function
    void *arg = (void *)(uintptr_t)(size > 0 ? data[0] : 0);

    // Call the sqlite3_profile function with the callback
    sqlite3_profile(db, profile_callback, arg);

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

    LLVMFuzzerTestOneInput_447(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
