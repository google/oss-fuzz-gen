#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Include the necessary headers for the function-under-test
extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

// Define the function-under-test signature
extern "C" size_t tj3YUVPlaneSize(int, int, int, int, int);

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int width = 1;  // Minimum valid value for width
    int height = 1; // Minimum valid value for height
    int subsamp = TJSAMP_444; // A valid subsampling option
    int align = 1;  // Minimum valid value for alignment
    int plane = 0;  // Assuming plane 0 is a valid plane

    // Call the function-under-test
    size_t result = tj3YUVPlaneSize(width, height, subsamp, align, plane);

    // Print the result (optional, for debugging purposes)
    printf("Result: %zu\n", result);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
