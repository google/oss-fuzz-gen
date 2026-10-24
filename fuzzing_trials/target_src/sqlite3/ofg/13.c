#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

extern int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Declare and initialize a sqlite3 pointer
    sqlite3 *db = NULL;

    // Open an in-memory SQLite database
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0; // If opening the database fails, return early
    }

    // Call the function-under-test
    int errno_result = sqlite3_system_errno(db);

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

    LLVMFuzzerTestOneInput_13(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
