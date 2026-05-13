#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int width = 1;
    int height = 1;
    int subsamp = TJSAMP_444; // Use a valid subsampling option
    int plane = 0;
    int align = 1;

    // Ensure that the data size is sufficient to extract meaningful values
    if (size >= 5) {
        // Extract values from the data to use as parameters
        width = static_cast<int>(data[0]) + 1;  // Avoid zero
        height = static_cast<int>(data[1]) + 1; // Avoid zero
        subsamp = static_cast<int>(data[2]) % 5; // Ensure subsamp is within valid range
        plane = static_cast<int>(data[3]) % 3;   // Typically 0-2 for YUV planes
        align = static_cast<int>(data[4]) + 1;   // Avoid zero
    }

    // Call the function-under-test
    unsigned long sizeYUV = tjPlaneSizeYUV(width, height, subsamp, plane, align);

    // Use the result to avoid compiler optimizations removing the call
    volatile unsigned long result = sizeYUV;
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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
