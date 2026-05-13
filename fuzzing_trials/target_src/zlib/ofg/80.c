#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to create an int64_t value
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Initialize the int64_t variable from the input data
    int64_t offset = 0;
    for (size_t i = 0; i < sizeof(int64_t); i++) {
        offset = (offset << 8) | data[i];
    }

    // Call the function-under-test
    uLong result = crc32_combine_gen64(offset);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
