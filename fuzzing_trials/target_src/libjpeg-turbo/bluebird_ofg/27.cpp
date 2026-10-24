#include <string.h>
#include <sys/stat.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Allocate a buffer for the decompressed image
    int width = 256;  // Example width
    int height = 256; // Example height
    int pixelFormat = TJPF_RGB;
    unsigned char *decompressedImage = static_cast<unsigned char *>(malloc(width * height * tjPixelSize[pixelFormat]));

    if (decompressedImage == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tjDecompress2(handle, data, size, decompressedImage, width, 0, height, pixelFormat, 0);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tjDecompress2 to tj3Compress12
    tjhandle ret_tjInitCompress_uapiw = tjInitCompress();
    size_t qlykyvwv = 1;
    // Ensure dataflow is valid (i.e., non-null)
    if (!decompressedImage) {
    	return 0;
    }
    int ret_tj3Compress12_peoyl = tj3Compress12(ret_tjInitCompress_uapiw, NULL, TJFLAG_FORCESSE2, TJXOPT_TRIM, TJXOPT_PERFECT, 0, &decompressedImage, &qlykyvwv);
    if (ret_tj3Compress12_peoyl < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    free(decompressedImage);
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
