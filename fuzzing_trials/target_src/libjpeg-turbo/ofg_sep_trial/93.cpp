#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    tjhandle handle = nullptr;
    int errorCode = 0;

    // Initialize the TurboJPEG decompressor
    handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Initialization failed, exit early
    }

    // Attempt to decompress the data to trigger potential errors
    // Note: We are not actually decompressing here, just simulating a call that could lead to an error
    // This is to ensure that tjGetErrorCode can be called meaningfully
    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;
    if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) != 0) {
        // If an error occurs, retrieve the error code
        errorCode = tjGetErrorCode(handle);
    }

    // Clean up
    tjDestroy(handle);

    return 0;
}