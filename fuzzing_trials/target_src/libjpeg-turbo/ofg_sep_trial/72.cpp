#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Initialize variables for tj3SaveImage16
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0; // Exit if handle initialization fails
    }

    const char *filename = "test_output.jpg"; // Output file name

    // Use the data to create a uint16_t array, assuming J16SAMPLE is a uint16_t
    if (size < sizeof(uint16_t)) {
        tj3Destroy(handle);
        return 0;
    }

    const uint16_t *sampleArray = reinterpret_cast<const uint16_t *>(data);

    // Set arbitrary non-zero dimensions and subsampling
    int width = 16;
    int height = 16;
    int pitch = width * sizeof(uint16_t);
    int subsamp = TJSAMP_444;

    // Call the function-under-test
    tj3SaveImage16(handle, filename, sampleArray, width, pitch, height, subsamp);

    // Clean up
    tj3Destroy(handle);

    return 0;
}