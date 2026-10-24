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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "../src/turbojpeg.h"

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz tj3Init
    int initType = Data[0] % 3;  // Assuming 0, 1, 2 are valid initTypes
    tjhandle handle = tj3Init(initType);

    if (handle) {
        // Fuzz tj3Alloc
        size_t allocSize = Size;
        void *buffer = tj3Alloc(allocSize);

        if (buffer) {
            // Fuzz tj3SetICCProfile
            unsigned char *iccBuf = (unsigned char *)Data;
            size_t iccSize = Size;
            tj3SetICCProfile(handle, iccBuf, iccSize);

            // Prepare dummy buffer for tj3Compress16
            size_t srcBufSize = Size / sizeof(unsigned short);
            unsigned short *srcBuf = (unsigned short *)malloc(srcBufSize * sizeof(unsigned short));
            if (srcBuf) {
                memcpy(srcBuf, Data, srcBufSize * sizeof(unsigned short));
                int width = srcBufSize % 100 + 1;  // Random width
                int height = srcBufSize % 100 + 1; // Random height
                int pixelFormat = TJPF_RGB;  // Assuming RGB format
                unsigned char *jpegBuf = nullptr;
                size_t jpegSize = 0;

                tj3Compress16(handle, srcBuf, width, 0, height, pixelFormat, &jpegBuf, &jpegSize);

                free(srcBuf);
                tj3Free(jpegBuf);
            }

            // Fuzz tj3Decompress16
            size_t dstBufSize = Size / sizeof(unsigned short);
            unsigned short *dstBuf = (unsigned short *)malloc(dstBufSize * sizeof(unsigned short));
            if (dstBuf) {
                int pitch = 0;
                int pixelFormat = TJPF_RGB;  // Assuming RGB format for decompression
                tj3Decompress16(handle, (unsigned char *)Data, Size, dstBuf, pitch, pixelFormat);
                free(dstBuf);
            }

            // Fuzz tj3Set
            int param = Data[0] % 10;  // Assuming 10 different parameters
            int value = Data[0] % 100; // Random value for the parameter
            tj3Set(handle, param, value);

            tj3Free(buffer);
        }

        // Clean up
        tj3Destroy(handle);
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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
