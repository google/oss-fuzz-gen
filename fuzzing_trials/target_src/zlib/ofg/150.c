#include <stdint.h>
#include <stddef.h>
#include <sys/types.h> // Include this for off_t
#include <zlib.h>

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract two uLong values and at least one byte for len2
    if (size < sizeof(uLong) * 2 + sizeof(uint8_t)) {
        return 0;
    }

    // Extract the first uLong value from the data
    uLong adler1 = *(const uLong *)data;
    data += sizeof(uLong);

    // Extract the second uLong value from the data
    uLong adler2 = *(const uLong *)data;
    data += sizeof(uLong);

    // Use the remaining data size as len2, ensuring it's non-zero
    off_t len2 = size - 2 * sizeof(uLong);

    // Call the adler32_combine function from zlib
    uLong result = adler32_combine(adler1, adler2, len2);

    // Use the result in some way to prevent the compiler from optimizing it away
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

    LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
