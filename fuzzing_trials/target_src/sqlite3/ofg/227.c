#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Helper function to create a temporary database
static sqlite3* create_temp_database() {
    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    return db;
}

int LLVMFuzzerTestOneInput_227(const uint8_t *data, size_t size) {
    sqlite3 *db = create_temp_database();
    if (db == NULL) {
        return 0;
    }

    // Ensure that data is null-terminated for use as a string
    char *wal_name = (char *)malloc(size + 1);
    if (wal_name == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(wal_name, data, size);
    wal_name[size] = '\0';

    // Call the function-under-test
    sqlite3_wal_checkpoint(db, wal_name);

    // Clean up
    free(wal_name);
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

    LLVMFuzzerTestOneInput_227(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
