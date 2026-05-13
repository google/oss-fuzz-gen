#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    tjhandle handle = tjInitDecompress();
    
    // Check if the handle was initialized successfully
    if (handle != nullptr) {
        // Perform some operations with the handle if needed
        // Example: Decompress the input data
        int width, height, jpegSubsamp, jpegColorspace;
        if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
            // Allocate buffer for decompressed image
            unsigned char *buffer = new unsigned char[width * height * tjPixelSize[TJPF_RGB]];
            if (buffer) {
                // Decompress the image
                tjDecompress2(handle, data, size, buffer, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);
                delete[] buffer;
            }
        }

        // Clean up and destroy the handle
        tjDestroy(handle);
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
