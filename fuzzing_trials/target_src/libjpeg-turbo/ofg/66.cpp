#include <cstdint>
#include <cstddef>

// Assume the function is defined in an external C library
extern "C" {
    size_t tj3YUVBufSize(int width, int height, int subsample, int align);
}

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract four integers
    if (size < 4 * sizeof(int)) {
        return 0;
    }

    // Extract four integers from the input data
    int width = ((int*)data)[0];
    int height = ((int*)data)[1];
    int subsample = ((int*)data)[2];
    int align = ((int*)data)[3];

    // Call the function-under-test
    size_t bufferSize = tj3YUVBufSize(width, height, subsample, align);

    // Use the result to prevent compiler optimizations from removing the function call
    volatile size_t result = bufferSize;
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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
