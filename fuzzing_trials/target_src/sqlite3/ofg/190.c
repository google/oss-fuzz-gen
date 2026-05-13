#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_str *str = NULL;

    // Initialize an in-memory SQLite database
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0; // If opening the database fails, exit early
    }

    // Call the function-under-test
    str = sqlite3_str_new(db);

    // If str is not NULL, append data to it
    if (str != NULL && data != NULL && size > 0) {
        sqlite3_str_appendf(str, "%.*s", (int)size, data);
    }

    // Clean up
    if (str != NULL) {
        sqlite3_str_finish(str);
    }
    if (db != NULL) {
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

    LLVMFuzzerTestOneInput_190(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
