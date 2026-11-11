#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Added for write, close, and unlink functions
#include <stdio.h>  // Added for mkstemp function

// Function to write fuzz data to a temporary file
static char *write_to_temp_file(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return NULL;
    }
    write(fd, data, size);
    close(fd);
    return strdup(tmpl);
}

int LLVMFuzzerTestOneInput_257(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *errMsg = NULL;
    char *fileName = NULL;

    // Initialize SQLite database in memory
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Write fuzz data to a temporary file
    fileName = write_to_temp_file(data, size);
    if (fileName == NULL) {
        sqlite3_close(db);
        return 0;
    }

    // Call the function-under-test
    sqlite3_load_extension(db, fileName, NULL, &errMsg);

    // Clean up
    if (errMsg != NULL) {
        sqlite3_free(errMsg);
    }
    if (fileName != NULL) {
        unlink(fileName);
        free(fileName);
    }
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

    LLVMFuzzerTestOneInput_257(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
