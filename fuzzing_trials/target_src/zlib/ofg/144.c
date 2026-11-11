#include <stdint.h>
#include <stddef.h>
#include <zlib.h> // Ensure zlib is included for uLong type and crc32_combine_op function

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract three uLong values
    if (size < 3 * sizeof(uLong)) {
        return 0;
    }

    // Extract three uLong values from the input data
    uLong crc1 = *(const uLong *)(data);
    uLong crc2 = *(const uLong *)(data + sizeof(uLong));
    uLong len2 = *(const uLong *)(data + 2 * sizeof(uLong));

    // Call the function-under-test
    uLong result = crc32_combine_op(crc1, crc2, len2);

    // Use the result in some way to avoid compiler optimizations removing the call
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

    LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
