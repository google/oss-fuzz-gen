#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio> // Include this for FILE type

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/jpeglib.h"
    #include "/src/libjpeg-turbo.3.0.x/jpeglib.h"
    #include "/src/libjpeg-turbo.main/src/jpeglib.h"
}

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    const char *filename = "output.tiff";
    int width = 1;  // Minimum valid width
    int height = 1; // Minimum valid height
    int pitch = width * sizeof(JSAMPLE);  // Use JSAMPLE instead of J16SAMPLE
    int flags = 0;

    // Ensure the data size is sufficient for at least one pixel
    if (size < static_cast<size_t>(width * height * sizeof(JSAMPLE))) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for image data
    JSAMPLE *imageData = new JSAMPLE[width * height];
    if (!imageData) {
        tjDestroy(handle);
        return 0;
    }

    // Copy data into imageData
    std::memcpy(imageData, data, width * height * sizeof(JSAMPLE));

    // Convert JSAMPLE data to unsigned short as required by tj3SaveImage16
    unsigned short *imageData16 = new unsigned short[width * height];
    for (int i = 0; i < width * height; i++) {
        imageData16[i] = static_cast<unsigned short>(imageData[i]) << 8; // Convert to 16-bit
    }

    // Call the function-under-test
    int result = tj3SaveImage16(handle, filename, imageData16, width, pitch, height, flags);

    // Clean up
    delete[] imageData;
    delete[] imageData16;
    tjDestroy(handle);

    return result;
}