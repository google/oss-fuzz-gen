#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput_329(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int result;
    char db_name[256];

    // Ensure the database name is not empty and fits within the buffer
    if (size > 0 && size < sizeof(db_name)) {
        memcpy(db_name, data, size);
        db_name[size] = '\0'; // Null-terminate the string

        // Call the function-under-test
        result = sqlite3_open(db_name, &db);

        // Close the database if it was opened
        if (result == SQLITE_OK && db != NULL) {
            sqlite3_close(db);
        }
    }

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

    LLVMFuzzerTestOneInput_329(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
