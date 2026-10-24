#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

// Define a simple collation function outside of LLVMFuzzerTestOneInput
int collationFunction(void *pCtx, int len1, const void *str1, int len2, const void *str2) {
    return strncmp((const char *)str1, (const char *)str2, len1 < len2 ? len1 : len2);
}

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Initialize variables
    sqlite3 *db;
    char *errMsg = 0;
    int rc;

    // Open a temporary in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        return 0;
    }

    // Ensure the data is null-terminated to form a valid string
    char collationName[256];
    size_t collationNameSize = size < 255 ? size : 255;
    memcpy(collationName, data, collationNameSize);
    collationName[collationNameSize] = '\0';

    // Call the function-under-test
    sqlite3_create_collation(db, collationName, SQLITE_UTF8, NULL, collationFunction);

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

    LLVMFuzzerTestOneInput_91(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
