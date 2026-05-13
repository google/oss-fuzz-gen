#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    int log = 0, ckpt = 0;
    char db_name[256] = {0};

    // Ensure the data size is sufficient for a meaningful test
    if (size < 1) {
        return 0;
    }

    // Create an in-memory database for testing
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Copy data into db_name, ensuring null-termination
    size_t copy_size = size < sizeof(db_name) - 1 ? size : sizeof(db_name) - 1;
    memcpy(db_name, data, copy_size);
    db_name[copy_size] = '\0';

    // Call the function-under-test
    sqlite3_wal_checkpoint_v2(db, db_name, SQLITE_CHECKPOINT_PASSIVE, &log, &ckpt);

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

    LLVMFuzzerTestOneInput_214(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
