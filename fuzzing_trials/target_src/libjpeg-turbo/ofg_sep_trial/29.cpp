#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    int tjSaveImage(const char *filename, unsigned char *buffer, int width, int pitch, int height, int pixelFormat, int flags);
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the parameters
    if (size < 20) {
        return 0;
    }

    // Extract parameters from the data
    const char *filename = reinterpret_cast<const char*>(data);
    unsigned char *buffer = const_cast<unsigned char*>(data + 5);
    int width = static_cast<int>(data[10]);
    int pitch = static_cast<int>(data[11]);
    int height = static_cast<int>(data[12]);
    int pixelFormat = static_cast<int>(data[13]);
    int flags = static_cast<int>(data[14]);

    // Call the function under test
    tjSaveImage(filename, buffer, width, pitch, height, pixelFormat, flags);

    return 0;
}