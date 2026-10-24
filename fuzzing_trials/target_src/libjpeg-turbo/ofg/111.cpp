#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for the output buffer
    int width = 640;  // Example width
    int height = 480; // Example height
    int numPlanes = 3; // YUV has 3 planes
    size_t outputBufferSize = width * height * numPlanes;
    unsigned char *outputBuffer = (unsigned char *)malloc(outputBufferSize);
    if (outputBuffer == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Ensure input data is not null and has a minimum size
    if (data == nullptr || size == 0) {
        free(outputBuffer);
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjDecompressToYUV(handle, (unsigned char *)data, (unsigned long)size, outputBuffer, width);

    // Clean up
    free(outputBuffer);
    tjDestroy(handle);

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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
