extern "C" {
    #include <stdint.h>
    #include <stddef.h>
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    if (size < 3) {
        // Not enough data to extract componentID, width, and subsampling
        return 0;
    }

    // Use input data to initialize parameters for tj3YUVPlaneWidth
    int componentID = data[0] % 3; // Assuming 3 components (Y, Cb, Cr)
    int width = (data[1] << 8) + data[2]; // Use two bytes for width

    // Use the remaining data size to determine subsampling
    int subsampling = (size > 3) ? data[3] % 5 : TJSAMP_420; // Assuming 5 subsampling types

    // Call the function-under-test
    int result = tj3YUVPlaneWidth(componentID, width, subsampling);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result < 0) {
        // Handle error case if necessary
    }

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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
