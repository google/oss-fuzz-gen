#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;
    int result = 0;

    // Ensure the handle is valid
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    result = tjDecompressHeader3(handle, data, (unsigned long)size, &width, &height, &jpegSubsamp, &jpegColorspace);

    // Clean up
    tjDestroy(handle);

    return 0;
}