#include <stdint.h>
#include <stddef.h>  // Include for size_t
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_276(const uint8_t *data, size_t size) {
    // Initialize SQLite database connection
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure size is sufficient to extract an integer for the second parameter
    if (size < sizeof(int)) {
        sqlite3_close(db);
        return 0;
    }

    // Extract an integer from the data for the second parameter
    int config_option = *(int *)data;

    // Use the remaining data as the third parameter
    void *config_value = (void *)(data + sizeof(int));

    // Call the function-under-test
    sqlite3_vtab_config(db, config_option, config_value);

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

    LLVMFuzzerTestOneInput_276(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
