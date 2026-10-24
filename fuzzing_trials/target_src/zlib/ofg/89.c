#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Initialize the adler parameter to a non-zero value
    uLong adler = 1;

    // Ensure the size is within the range of uInt
    if (size > UINT32_MAX) {
        size = UINT32_MAX;
    }

    // Call the function-under-test
    uLong result = adler32(adler, (const Bytef *)data, (uInt)size);

    // Use the result in some way to prevent compiler optimizations from removing the call
    // For fuzzing purposes, we typically don't need to do anything with the result
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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
