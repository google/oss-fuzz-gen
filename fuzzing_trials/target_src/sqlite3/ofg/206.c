#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_206(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    int limit_id;
    int new_value;

    // Open a new in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure size is sufficient to extract limit_id and new_value
    if (size < sizeof(int) * 2) {
        sqlite3_close(db);
        return 0;
    }
    
    // Extract limit_id and new_value from the input data
    limit_id = *((int *)data);
    new_value = *((int *)(data + sizeof(int)));

    // Call the function-under-test
    sqlite3_limit(db, limit_id, new_value);

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

    LLVMFuzzerTestOneInput_206(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
