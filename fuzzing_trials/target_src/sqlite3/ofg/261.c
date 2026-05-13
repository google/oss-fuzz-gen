#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_261(const uint8_t *data, size_t size) {
    // Ensure that the size of data is at least 1 byte to extract an integer value
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to determine the integer value
    // This will ensure that the value is always 0 or 1
    int enable = data[0] % 2;

    // Call the function-under-test
    sqlite3_enable_shared_cache(enable);

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

    LLVMFuzzerTestOneInput_261(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
