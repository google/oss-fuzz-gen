#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    // Include the necessary headers for the function-under-test
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

// Function-under-test signature
extern "C" unsigned long tjBufSize(int width, int height, int jpegSubsamp);

extern "C" int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    int width = 1;    // Minimum width
    int height = 1;   // Minimum height
    int jpegSubsamp = TJSAMP_444; // One of the valid subsampling options

    // Call the function-under-test
    unsigned long bufferSize = tjBufSize(width, height, jpegSubsamp);

    // Print the result (for debugging purposes)
    printf("Buffer Size: %lu\n", bufferSize);

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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
