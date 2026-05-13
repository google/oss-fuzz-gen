#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitDecompress();
    unsigned char *jpegBuf = (unsigned char *)data;
    unsigned long jpegSize = (unsigned long)size;
    int width = 0;
    int height = 0;

    // Ensure handle is not NULL
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = tjDecompressHeader(handle, jpegBuf, jpegSize, &width, &height);

    // Clean up
    tjDestroy(handle);

    return 0;
}