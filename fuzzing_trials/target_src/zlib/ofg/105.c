#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract three values
    if (size < sizeof(uLong) * 2 + sizeof(off_t)) {
        return 0;
    }

    // Extract the first uLong value
    uLong crc1 = *((uLong *)data);
    data += sizeof(uLong);

    // Extract the second uLong value
    uLong crc2 = *((uLong *)data);
    data += sizeof(uLong);

    // Extract the off_t value
    off_t len2 = *((off_t *)data);

    // Call the function-under-test
    uLong combined_crc = crc32_combine(crc1, crc2, len2);

    // Use the result in some way to avoid compiler optimizations
    (void)combined_crc;

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

    LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
