#include <cstdint>
#include <cstddef>
#include <cstdio>

// Assuming the function is defined in an external C library
extern "C" {
    size_t tj3YUVBufSize(int width, int height, int subsamp, int align);
}

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int width = 1;
    int height = 1;
    int subsamp = 0;
    int align = 1;

    // Ensure the data size is sufficient to extract needed values
    if (size >= 4) {
        // Extract values from the data for fuzzing
        width = static_cast<int>(data[0]) + 1;  // Avoid zero width
        height = static_cast<int>(data[1]) + 1; // Avoid zero height
        subsamp = static_cast<int>(data[2]) % 4; // Assuming subsamp ranges from 0 to 3
        align = static_cast<int>(data[3]) + 1;   // Avoid zero alignment
    }

    // Call the function-under-test
    size_t bufSize = tj3YUVBufSize(width, height, subsamp, align);

    // Output the result for debugging purposes
    printf("Buffer Size: %zu\n", bufSize);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
