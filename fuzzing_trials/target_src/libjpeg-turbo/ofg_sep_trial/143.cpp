#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < 10) return 0;

    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) return 0;

    // Extract parameters from the input data
    int width = data[0] + 1; // Ensure non-zero width
    int height = data[1] + 1; // Ensure non-zero height
    int strides[3] = {width, width / 2, width / 2}; // YUV strides
    int subsamp = TJSAMP_420; // Use a common subsampling format
    int flags = 0; // No flags

    // Allocate memory for the output buffer
    unsigned char* dstBuf = (unsigned char*)malloc(width * height * 3);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjDecodeYUV(handle, data, strides[0], strides[1], dstBuf, width, 0, height, TJPF_RGB, flags);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}