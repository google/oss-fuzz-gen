#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Initialize parameters for tj3SaveImage16
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data size is sufficient for a minimal image
    if (size < 6) {
        tj3Destroy(handle);
        return 0;
    }

    // Use a portion of the data as a filename (null-terminated)
    const char *filename = reinterpret_cast<const char *>(data);
    size_t filename_len = strnlen(filename, size);
    if (filename_len == size) {
        tj3Destroy(handle);
        return 0;
    }

    // Use the rest of the data as image samples
    const uint16_t *samples = reinterpret_cast<const uint16_t *>(data + filename_len + 1);
    size_t samples_size = size - filename_len - 1;

    // Define image dimensions and other parameters
    int width = 2;  // Minimal width
    int height = 2; // Minimal height
    int pitch = width * sizeof(uint16_t);
    int flags = 0;  // No specific flags

    // Call the function-under-test
    tj3SaveImage16(handle, filename, samples, width, pitch, height, flags);

    // Clean up
    tj3Destroy(handle);

    return 0;
}