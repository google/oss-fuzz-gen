#include <stdint.h>
#include <stddef.h>
#include <zlib.h> // Ensure to include zlib.h for crc32_combine

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Check if size is sufficient to split data for crc1 and crc2
    if (size < 8) {
        return 0; // Not enough data to proceed
    }

    // Extract crc1 and crc2 from the input data
    uLong crc1 = *(const uLong *)data;
    uLong crc2 = *(const uLong *)(data + 4);

    // Use the remaining data length as len2
    off_t len2 = (off_t)(size - 8);

    // Call the function-under-test
    uLong result = crc32_combine(crc1, crc2, len2);

    // Use the result in some way to avoid compiler optimizations
    if (result == 0) {
        return 0;
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
