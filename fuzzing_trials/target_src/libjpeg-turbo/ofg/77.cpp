#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // for malloc and free

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Initialize the decompression handle
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);

    // Ensure that the handle is not NULL before proceeding
    if (handle != NULL) {
        // Attempt to decompress the input data
        int width, height, jpegSubsamp, jpegColorspace;
        unsigned long jpegSize = size;
        
        // Allocate a buffer for the decompressed image
        unsigned char *dstBuf = NULL;
        
        // Use tjDecompressHeader3 to read the header and get image info
        if (tjDecompressHeader3(handle, (unsigned char *)data, jpegSize, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
            // Allocate buffer for decompressed image
            dstBuf = (unsigned char *)malloc(width * height * tjPixelSize[TJPF_RGB]);
            
            if (dstBuf != NULL) {
                // Decompress the image
                tjDecompress2(handle, (unsigned char *)data, jpegSize, dstBuf, width, 0, height, TJPF_RGB, 0);
                
                // Free the decompressed buffer
                free(dstBuf);
            }
        }
        
        // Destroy the handle
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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
