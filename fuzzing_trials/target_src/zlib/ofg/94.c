#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <sys/types.h> // Include for off64_t
#include <unistd.h>    // Include for off64_t

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    if (size < sizeof(uLong) * 2 + sizeof(off_t)) {
        return 0; // Not enough data to extract three required values
    }

    // Extract uLong values from the input data
    uLong crc1 = *(const uLong *)(data);
    uLong crc2 = *(const uLong *)(data + sizeof(uLong));

    // Extract off_t value from the input data
    off_t len2 = *(const off_t *)(data + 2 * sizeof(uLong));

    // Call the function-under-test
    uLong combined_crc = crc32_combine(crc1, crc2, (z_off_t)len2);

    // Use the result in some way to avoid compiler optimizations
    // that might remove the function call
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

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
