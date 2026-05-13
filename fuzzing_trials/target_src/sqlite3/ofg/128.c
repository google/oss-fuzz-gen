#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // For close() and unlink()
#include <stdlib.h> // For mkstemp()

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Create a temporary file to act as the database
    char tmpl[] = "/tmp/fuzzdbXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) return 0;
    close(fd);

    // Ensure the filename is null-terminated
    tmpl[sizeof(tmpl) - 1] = '\0';

    // Prepare the flags and vfs arguments
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    const char *vfs = NULL;

    // Initialize the SQLite database pointer
    sqlite3 *db = NULL;

    // Call the function-under-test
    int result = sqlite3_open_v2(tmpl, &db, flags, vfs);

    // Clean up
    if (db) {
        sqlite3_close(db);
    }
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

    LLVMFuzzerTestOneInput_128(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
