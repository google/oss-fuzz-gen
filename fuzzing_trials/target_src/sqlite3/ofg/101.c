#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const void *tail = NULL;
    int rc;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure the data is not empty and can be interpreted as a UTF-16 string
    if (size < 2 || size % 2 != 0) {
        sqlite3_close(db);
        return 0;
    }

    // Prepare the statement using the function-under-test
    rc = sqlite3_prepare16_v3(db, data, size, 0, &stmt, &tail);

    // Finalize the statement if it was prepared successfully
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

    // Close the database connection
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

    LLVMFuzzerTestOneInput_101(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
