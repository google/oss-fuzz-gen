#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the parameters of tjBufSizeYUV2
    int width = 1;
    int height = 1;
    int subsamp = TJSAMP_444; // Use a valid subsampling option
    int align = 1;

    // Ensure that the input size is sufficient to extract meaningful data
    if (size >= 4) {
        // Extract values from the input data to vary the parameters
        width = (int)data[0] + 1;  // Avoid zero width
        height = (int)data[1] + 1; // Avoid zero height
        subsamp = (int)(data[2] % 5); // Valid subsampling values are 0 to 4
        align = (int)(data[3] % 4) + 1; // Valid alignment values are 1 to 4
    }

    // Call the function-under-test
    unsigned long bufSize = tjBufSizeYUV2(width, height, subsamp, align);

    // Use bufSize in some way to avoid compiler optimizations removing the call
    (void)bufSize;

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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
