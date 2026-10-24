#include <stdint.h>
#include <stddef.h> // Include for size_t
#include <stdlib.h> // Include for NULL
#include <sqlite3.h>

// Dummy callback function to pass as the third argument
void collation_needed_callback_177(void *pArg, sqlite3 *db, int eTextRep, const char *zCollName) {
    // This function is a placeholder and does nothing
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Use the data as a pointer to pass as the second argument
    void *pArg = (void *)data;

    // Call the function-under-test
    sqlite3_collation_needed(db, pArg, collation_needed_callback_177);

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

    LLVMFuzzerTestOneInput_177(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
