#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;

    // Ensure the input data is non-zero size for a valid filename
    if (size == 0) {
        return 0;
    }

    // Create a temporary filename using the input data
    char filename[256];
    size_t filename_length = size < 255 ? size : 255;
    for (size_t i = 0; i < filename_length; ++i) {
        filename[i] = (char)data[i];
    }
    filename[filename_length] = '\0';

    // Attempt to open a SQLite database with the filename
    rc = sqlite3_open(filename, &db);

    // If the database was opened successfully, attempt to close it
    if (rc == SQLITE_OK) {
        sqlite3_close_v2(db);
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

    LLVMFuzzerTestOneInput_61(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
