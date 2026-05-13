#include <stdint.h>
#include <stddef.h> // Include this for size_t
#include <sqlite3.h>

// Dummy callback function to be used as the rollback hook
void rollback_callback(void *data) {
    // Do nothing
}

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Use the first part of the data as the void* argument
    void *hook_data = (void *)data;

    // Set the rollback hook with the dummy callback
    sqlite3_rollback_hook(db, rollback_callback, hook_data);

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

    LLVMFuzzerTestOneInput_131(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
