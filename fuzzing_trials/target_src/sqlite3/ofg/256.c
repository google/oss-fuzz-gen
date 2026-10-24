#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_256(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    int config_option;
    void *config_value;

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Ensure size is sufficient for extracting an int and a pointer-sized value
    if (size < sizeof(int) + sizeof(void *)) {
        sqlite3_close(db);
        return 0;
    }

    // Extract an integer from the data for the config option
    config_option = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract a pointer-sized value from the data for the config value
    config_value = (void *)*(uintptr_t *)data;

    // Call the function-under-test
    sqlite3_db_config(db, config_option, config_value);

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

    LLVMFuzzerTestOneInput_256(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
