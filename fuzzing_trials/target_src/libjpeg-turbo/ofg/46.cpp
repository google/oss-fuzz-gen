#include <cstdint>
#include <cstdlib>
#include <cstring>

// Ensure C linkage for the function-under-test and include the correct header
extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Call the function-under-test
    tjhandle handle = tjInitCompress();

    // Check if the handle is NULL, which indicates an error in initialization
    if (handle == nullptr) {
        return 0;
    }

    // Prepare a dummy image buffer for compression
    int width = 100; // Example width
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    unsigned char *srcBuf = new unsigned char[width * height * 3];
    std::memset(srcBuf, 0, width * height * 3); // Initialize buffer with zeros

    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    int jpegSubsamp = TJSAMP_444; // Example subsampling
    int jpegQual = 75; // Example quality
    int flags = 0; // Example flags

    // Compress the dummy image
    tjCompress2(handle, srcBuf, width, 0, height, pixelFormat, &jpegBuf, &jpegSize, jpegSubsamp, jpegQual, flags);

    // Clean up
    tjDestroy(handle);
    tjFree(jpegBuf);
    delete[] srcBuf;

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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
