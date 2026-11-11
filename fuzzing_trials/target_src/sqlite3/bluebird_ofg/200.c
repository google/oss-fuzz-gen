#include <sys/stat.h>
#include <stdint.h>
#include "sqlite3.h"
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_200(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const void *tail = NULL;
    int rc;

    // Open an in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;  // If opening the database fails, exit early
    }

    // Ensure the data is not NULL and has a size greater than 0
    if (data != NULL && size > 0) {
        // Allocate memory for a UTF-16 buffer
        size_t utf16_size = size * 2;
        uint16_t *utf16_data = (uint16_t *)malloc(utf16_size + 2); // +2 for null terminator

        if (utf16_data != NULL) {
            // Convert the input data to UTF-16 (simple conversion for demonstration)
            for (size_t i = 0; i < size; ++i) {
                utf16_data[i] = (uint16_t)data[i];
            }
            utf16_data[size] = 0; // Null-terminate the UTF-16 string

            // Prepare the SQL statement using the fuzzing data
            rc = sqlite3_prepare16_v2(db, utf16_data, (int)utf16_size, &stmt, &tail);

            // Finalize the statement if it was successfully prepared
            if (stmt != NULL) {
                sqlite3_finalize(stmt);
            }

            // Free the allocated UTF-16 buffer
            free(utf16_data);
        }
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

    LLVMFuzzerTestOneInput_200(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
