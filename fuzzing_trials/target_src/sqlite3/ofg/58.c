#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 2) {
        return 0;
    }

    // Initialize a sqlite3_str object
    sqlite3_str *pStr = sqlite3_str_new(NULL);

    // Use part of the data as the string to append
    const char *str = (const char *)data;
    int strLength = size > 100 ? 100 : size; // Limit the length to avoid excessive memory usage

    // Call the function-under-test
    sqlite3_str_append(pStr, str, strLength);

    // Clean up
    sqlite3_str_finish(pStr);

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

    LLVMFuzzerTestOneInput_58(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
