#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_330(const uint8_t *data, size_t size) {
    char *filename;
    sqlite3 *db;
    int rc;

    // Ensure the data is null-terminated and not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the filename and ensure it's null-terminated
    filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        return 0;
    }
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Call the function-under-test
    rc = sqlite3_open(filename, &db);

    // Cleanup
    if (rc == SQLITE_OK) {
        sqlite3_close(db);
    }
    free(filename);

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

    LLVMFuzzerTestOneInput_330(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
