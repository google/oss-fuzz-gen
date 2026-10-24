#include <stdint.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a valid UTF-16 string
    if (size < 2) {
        return 0;
    }

    // Allocate memory for a UTF-16 string, ensuring it's null-terminated
    void *utf16_str = malloc(size + 2);
    if (!utf16_str) {
        return 0;
    }

    // Copy the data into the UTF-16 string buffer
    memcpy(utf16_str, data, size);
    // Null-terminate the UTF-16 string
    ((uint16_t *)utf16_str)[size / 2] = 0;

    sqlite3 *db = NULL;

    // Call the function-under-test
    int result = sqlite3_open16(utf16_str, &db);

    // Clean up
    if (db) {
        sqlite3_close(db);
    }
    free(utf16_str);

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

    LLVMFuzzerTestOneInput_93(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
