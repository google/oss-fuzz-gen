#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" {
    int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
        // Check if there is enough data to form a valid input
        if (size < sizeof(uint16_t)) {
            return 0; // Not enough data to form a valid input
        }

        // Initialize TurboJPEG handle
        tjhandle handle = tjInitCompress();
        if (handle == nullptr) {
            return 0; // Failed to initialize TurboJPEG
        }

        // Prepare input parameters
        const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data);
        int width = 1;  // Minimum width
        int height = 1; // Minimum height
        int pitch = width * sizeof(uint16_t);
        int pixelFormat = TJPF_RGB; // RGB pixel format

        // Allocate memory for compressed image
        unsigned char *jpegBuf = nullptr;
        size_t jpegSize = 0;

        // Call the function-under-test
        int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

        // Clean up
        if (jpegBuf != nullptr) {
            tjFree(jpegBuf);
        }
        tjDestroy(handle);

        return 0;
    }
}