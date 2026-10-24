#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize TurboJPEG decompressor
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Prepare variables to hold the image dimensions and subsampling
    int width = 0;
    int height = 0;
    int jpegSubsamp = 0;

    // Call the function under test
    int result = tjDecompressHeader2(handle, (unsigned char *)data, (unsigned long)size, &width, &height, &jpegSubsamp);

    // Clean up TurboJPEG handle
    tjDestroy(handle);

    return 0;
}