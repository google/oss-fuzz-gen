#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is defined in a C library
extern "C" {
    size_t tj3JPEGBufSize(int width, int height, int jpegSubsamp);
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract integers from the input data
    int width = *((int*)data);
    int height = *((int*)(data + sizeof(int)));
    int jpegSubsamp = *((int*)(data + 2 * sizeof(int)));

    // Call the function-under-test
    size_t bufferSize = tj3JPEGBufSize(width, height, jpegSubsamp);

    // Print the result for debugging purposes
    printf("Buffer size: %zu\n", bufferSize);

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
