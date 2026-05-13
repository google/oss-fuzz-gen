#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Not enough data to process
    }

    // Extract width, height, and subsampling from the input data
    int width = data[0] + 1;  // Ensure minimum width of 1
    int height = data[1] + 1; // Ensure minimum height of 1
    int subsamp = data[2] % TJSAMP_UNKNOWN; // Ensure a valid subsampling option
    int align = 1; // Minimum alignment
    int plane = 0; // Typically, the first plane is 0

    // Call the function-under-test with the initialized parameters
    size_t planeSize = tj3YUVPlaneSize(width, height, subsamp, align, plane);

    // Use the result in some way to avoid any compiler optimizations
    (void)planeSize;

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
