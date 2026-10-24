#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_215(const uint8_t *data, size_t size) {
    sqlite3 *db;
    int rc;
    int logFrameCount = 0;
    int checkpointCount = 0;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a temporary filename for the database
    char *filename = (char *)malloc(size + 1);
    if (!filename) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Ensure the filename is valid by replacing any null bytes
    for (size_t i = 0; i < size; i++) {
        if (filename[i] == '\0') {
            filename[i] = 'a'; // Replace null byte with a valid character
        }
    }

    // Call the function under test
    sqlite3_wal_checkpoint_v2(db, filename, SQLITE_CHECKPOINT_PASSIVE, &logFrameCount, &checkpointCount);

    // Clean up
    free(filename);
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

    LLVMFuzzerTestOneInput_215(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
