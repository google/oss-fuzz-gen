#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
        // Initialize variables for tj3Compress16 function
        tjhandle handle = tjInitCompress();
        if (!handle) return 0;

        // Use TJPF_RGBX to ensure 4 bytes per pixel, which matches the J16SAMPLE size
        const int pixelFormat = TJPF_RGBX;
        const int bytesPerPixel = tjPixelSize[pixelFormat];
        
        // Ensure that the input data size is sufficient for at least a 1x1 image
        if (size < bytesPerPixel) {
            tjDestroy(handle);
            return 0;
        }

        // Convert the input data to unsigned short as required by tj3Compress16
        const unsigned short *srcBuf = reinterpret_cast<const unsigned short *>(data);
        int width = 1; // Minimum width
        int pitch = width * bytesPerPixel;
        int height = 1; // Minimum height

        unsigned char *compressedBuf = nullptr;
        size_t compressedSize = 0;

        // Call the function-under-test
        int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &compressedBuf, &compressedSize);

        // Clean up
        tjFree(compressedBuf);
        tjDestroy(handle);

        return result;
    }
}