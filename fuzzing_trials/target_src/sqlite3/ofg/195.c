#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_195(const uint8_t *data, size_t size) {
    if (size < sizeof(sqlite3_uint64)) {
        return 0;
    }

    // Use the first 8 bytes of data as the input for sqlite3_malloc64
    sqlite3_uint64 input_size = *(const sqlite3_uint64 *)data;

    // Call the function-under-test
    void *result = sqlite3_malloc64(input_size);

    // Free the allocated memory if not NULL
    if (result != NULL) {
        sqlite3_free(result);
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

    LLVMFuzzerTestOneInput_195(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
