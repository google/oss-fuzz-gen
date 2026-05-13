#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdarg.h>

static sqlite3* initialize_db() {
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return NULL;
    }
    return db;
}

int LLVMFuzzerTestOneInput_284(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db = initialize_db();
    if (!db) return 0;

    // Step 1: Create a new dynamic string object
    sqlite3_str *strObj = sqlite3_str_new(db);
    if (!strObj) {
        sqlite3_close(db);
        return 0;
    }

    // Step 2: Append all data to the string object using a null-terminated buffer
    // Ensure null-termination for safe usage with string functions
    char *safeData = (char *)malloc(Size + 1);
    if (safeData) {
        memcpy(safeData, Data, Size);
        safeData[Size] = '\0';

        // Append formatted text to the string object using the safeData
        const char *format = "%s";
        sqlite3_str_appendf(strObj, format, safeData);

        sqlite3_str_appendall(strObj, safeData);
        free(safeData);
    }

    // Step 3: Reset the string object
    sqlite3_str_reset(strObj);

    // Step 4: Finalize the string object
    char *finalizedStr = sqlite3_str_finish(strObj);
    if (finalizedStr) {
        sqlite3_free(finalizedStr);
    }

    // Note: Do not call sqlite3_str_free after sqlite3_str_finish as it invalidates the object

    // Cleanup: Close the database connection
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

    LLVMFuzzerTestOneInput_284(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
