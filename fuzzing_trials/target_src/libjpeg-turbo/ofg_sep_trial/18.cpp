#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio> // Include for FILE operations

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Initialize variables for the function call
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Create a temporary file to simulate an image file
    const char *filename = "temp_image.ppm";
    FILE *file = fopen(filename, "wb");
    if (file == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Write the input data to the file
    fwrite(data, 1, size, file);
    fclose(file);

    // Initialize other parameters
    int width = 0;
    int pitch = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB;

    // Call the function-under-test
    unsigned short *image = tj3LoadImage16(handle, filename, &width, pitch, &height, &pixelFormat);

    // Clean up
    if (image != nullptr) {
        tjFree(reinterpret_cast<unsigned char*>(image)); // Cast to unsigned char* for tjFree
    }
    tjDestroy(handle);

    // Remove the temporary file
    remove(filename);

    return 0;
}