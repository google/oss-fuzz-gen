#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>  // Include the standard library for malloc and free

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Initialize a tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;  // Return if initialization fails
    }

    // Check if the input data is not null and size is greater than zero
    if (data != NULL && size > 0) {
        int width, height, jpegSubsamp, jpegColorspace;
        
        // Attempt to decompress the header
        if (tjDecompressHeader3(handle, data, size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
            // Allocate buffer for decompressed image
            unsigned char *buffer = (unsigned char *)malloc(width * height * tjPixelSize[TJPF_RGB]);
            if (buffer != NULL) {
                // Decompress the image
                tjDecompress2(handle, data, size, buffer, width, 0, height, TJPF_RGB, TJFLAG_FASTDCT);
                free(buffer);
            }
        }
    }

    // Clean up and destroy the handle
    tjDestroy(handle);

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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
