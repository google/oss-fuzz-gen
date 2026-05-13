#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // Include unistd.h for close() and unlink() functions

int LLVMFuzzerTestOneInput_258(const uint8_t *data, size_t size) {
    sqlite3 *db;
    char *errMsg = NULL;
    int rc;

    // Open a temporary in-memory database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Create a temporary file to store the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        sqlite3_close(db);
        return 0;
    }
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        close(fd);
        sqlite3_close(db);
        return 0;
    }
    fwrite(data, 1, size, f);
    fclose(f);

    // Attempt to load the extension using the fuzz data as the filename
    sqlite3_load_extension(db, tmpl, NULL, &errMsg);

    // Clean up
    if (errMsg) {
        sqlite3_free(errMsg);
    }
    sqlite3_close(db);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_258(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
