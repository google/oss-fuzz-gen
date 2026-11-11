#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Ensure that size is large enough to accommodate the required data
    if (size < sizeof(uint16_t) + 5 * sizeof(int)) {
        return 0;
    }

    // Initialize tjhandle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) {
        return 0;
    }

    // Extract parameters from data
    const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data);
    int width = data[0] % 256 + 1;  // Ensure width is at least 1
    int height = data[1] % 256 + 1; // Ensure height is at least 1
    int pitch = width * sizeof(uint16_t);
    int pixelFormat = data[2] % TJ_NUMPF; // Ensure pixel format is valid
    int flags = data[3] % 2 == 0 ? 0 : TJFLAG_FASTDCT; // Example flag

    // Allocate memory for the compressed image
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Prepare a valid source buffer with enough data
    // Ensure that the srcBuf is large enough for the given width and height
    size_t srcBufSize = width * height * sizeof(uint16_t);
    if (size < srcBufSize + sizeof(uint16_t) + 5 * sizeof(int)) {
        tj3Destroy(handle);
        return 0;
    }

    // Create a valid source buffer with data
    uint16_t *validSrcBuf = new uint16_t[width * height];
    memcpy(validSrcBuf, srcBuf, srcBufSize);

    // Call the function-under-test
    int result = tj3Compress16(handle, validSrcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

    // Clean up
    delete[] validSrcBuf;
    if (jpegBuf) {
        tj3Free(jpegBuf);
    }
    tj3Destroy(handle);

    // Ensure that the function is actually doing work by checking the result and jpegSize
    if (result == 0 && jpegSize > 0) {
        return 1; // Indicate success if compression was successful and produced output
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

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
