#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../src/turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize variables for tj3SaveImage16 and tj3LoadImage16
    tjhandle handle = nullptr;
    const char *filename = "./dummy_file";
    const unsigned short *buffer = reinterpret_cast<const unsigned short *>(Data);
    int width = 256;  // Arbitrary width for testing
    int height = 256; // Arbitrary height for testing
    int pixelFormat = TJPF_RGB;
    int pitch = width * tjPixelSize[pixelFormat]; // Calculate pitch based on width and pixel format

    // Write data to a dummy file for tj3SaveImage16 and tj3LoadImage16
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // 1. Test tj3GetErrorStr
    char *errorStr1 = tj3GetErrorStr(nullptr);

    // 2. Test tj3SaveImage16
    int saveResult = tj3SaveImage16(handle, filename, buffer, width, pitch, height, pixelFormat);
    if (saveResult == -1) {
        // Retrieve error if any
        char *errorStr2 = tj3GetErrorStr(handle);
    }

    // 3. Test tjLoadImage
    int loadedWidth = 0, loadedHeight = 0, loadedPixelFormat = 0;
    unsigned char *loadedImage = tjLoadImage(filename, &loadedWidth, 1, &loadedHeight, &loadedPixelFormat, 0);
    if (loadedImage) {
        tjFree(loadedImage);
    } else {
        // Retrieve error if any
        char *errorStr3 = tj3GetErrorStr(nullptr);
    }

    // 4. Test tjGetErrorStr2

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tjLoadImage to tj3Compress12
    tjhandle ret_tj3Init_gwcqu = tj3Init(0);
    size_t zipweqfv = Size;
    // Ensure dataflow is valid (i.e., non-null)
    if (!loadedImage) {
    	return 0;
    }
    int ret_tj3Compress12_mifgr = tj3Compress12(ret_tj3Init_gwcqu, NULL, TJFLAG_FORCESSE, TJFLAG_FORCESSE3, TJ_NUMINIT, TJ_BGR, &loadedImage, &zipweqfv);
    if (ret_tj3Compress12_mifgr < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char *errorStr4 = tjGetErrorStr2(handle);

    // 5. Test tj3LoadImage16
    int loadedWidth16 = 0, loadedHeight16 = 0, loadedPixelFormat16 = TJPF_UNKNOWN;
    unsigned short *loadedImage16 = tj3LoadImage16(handle, filename, &loadedWidth16, 1, &loadedHeight16, &loadedPixelFormat16);
    if (loadedImage16) {
        tj3Free(loadedImage16);
    } else {
        // Retrieve error if any
        char *errorStr5 = tj3GetErrorStr(nullptr);
    }

    // 6. Test tjSaveImage
    size_t bufferSize = width * height * tjPixelSize[pixelFormat];
    if (Size >= bufferSize) {
        unsigned char *imageBuffer = reinterpret_cast<unsigned char *>(const_cast<uint8_t *>(Data));
        int saveImageResult = tjSaveImage(filename, imageBuffer, width, pitch, height, pixelFormat, 0);
        if (saveImageResult == -1) {
            // Retrieve error if any
            char *errorStr6 = tj3GetErrorStr(nullptr);
        }
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
