#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_282(const uint8_t *data, size_t size) {
    sqlite3 *srcDb = NULL;
    sqlite3 *destDb = NULL;
    sqlite3_backup *backup = NULL;
    int rc;
    
    // Create source and destination databases in memory
    rc = sqlite3_open(":memory:", &srcDb);
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    rc = sqlite3_open(":memory:", &destDb);
    if (rc != SQLITE_OK) {
        sqlite3_close(srcDb);
        return 0;
    }
    
    // Ensure the data is null-terminated for use as a table name
    char tableName[256];
    if (size < sizeof(tableName)) {
        memcpy(tableName, data, size);
        tableName[size] = '\0';
    } else {
        memcpy(tableName, data, sizeof(tableName) - 1);
        tableName[sizeof(tableName) - 1] = '\0';
    }
    
    // Initialize the backup process
    backup = sqlite3_backup_init(destDb, "main", srcDb, tableName);
    
    // If backup is initialized, finalize it
    if (backup) {
        sqlite3_backup_finish(backup);
    }
    
    // Close the databases
    sqlite3_close(srcDb);
    sqlite3_close(destDb);
    
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

    LLVMFuzzerTestOneInput_282(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
