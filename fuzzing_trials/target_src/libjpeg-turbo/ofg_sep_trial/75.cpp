#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Failed to initialize, exit early
    }

    int width = 0;
    int height = 0;
    int jpegSubsamp = 0;
    int jpegColorspace = 0;

    // Call the function-under-test
    int result = tjDecompressHeader3(handle, data, (unsigned long)size, &width, &height, &jpegSubsamp, &jpegColorspace);

    // Clean up the TurboJPEG decompressor handle
    tjDestroy(handle);

    return 0;
}