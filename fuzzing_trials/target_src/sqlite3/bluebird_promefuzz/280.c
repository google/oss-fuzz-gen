#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sqlite3.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_280(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write dummy file if needed
    write_dummy_file(Data, Size);

    // Prepare strings from input data
    char *zDatabase = strndup((const char *)Data, Size);
    char *zJournal = strndup((const char *)Data, Size);
    char *zWal = strndup((const char *)Data, Size);

    // Prepare URI parameters
    const char *azParam[2] = { "key", "value" };

    // Test sqlite3_create_filename
    sqlite3_filename filename = sqlite3_create_filename(zDatabase, zJournal, zWal, 1, azParam);
    if (filename) {
        // Test sqlite3_filename_database
        const char *dbFilename = sqlite3_filename_database(filename);

        // Test sqlite3_filename_journal
        const char *journalFilename = sqlite3_filename_journal(filename);

        // Test sqlite3_filename_wal
        const char *walFilename = sqlite3_filename_wal(filename);

        // Test sqlite3_uri_parameter
        const char *paramValue = sqlite3_uri_parameter(filename, "key");

        // Free created filename
        sqlite3_free_filename(filename);
    }

    // Clean up
    free(zDatabase);
    free(zJournal);
    free(zWal);

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

    LLVMFuzzerTestOneInput_280(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
