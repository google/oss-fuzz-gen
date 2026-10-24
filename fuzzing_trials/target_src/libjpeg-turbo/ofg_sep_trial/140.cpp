#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data size is sufficient for decompression
    if (size < 100) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the decompressed image
    int width = 100;  // Example width
    int height = 100; // Example height
    unsigned char *dest = new unsigned char[width * height * 3]; // Assuming 3 components (RGB)

    // Call the function-under-test
    int result = tjDecompress2(handle, data, size, dest, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);

    // Clean up
    delete[] dest;
    tjDestroy(handle);

    return 0;
}