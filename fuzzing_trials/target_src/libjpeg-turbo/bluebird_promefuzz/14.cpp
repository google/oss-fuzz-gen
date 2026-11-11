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
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's data to process

    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    // Allocate variables to hold image information
    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;
    unsigned char *iccBuf = nullptr;
    size_t iccSize = 0;

    // Test tjDecompressHeader2
    tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &jpegSubsamp);

    // Test tjDecompressHeader3
    tjDecompressHeader3(handle, Data, Size, &width, &height, &jpegSubsamp, &jpegColorspace);

    // Test tj3DecompressHeader
    tj3DecompressHeader(handle, Data, Size);

    // Test tj3GetICCProfile
    tj3GetICCProfile(handle, &iccBuf, &iccSize);
    if (iccBuf) tj3Free(iccBuf);

    // Test tjDecompressHeader
    tjDecompressHeader(handle, const_cast<unsigned char*>(Data), Size, &width, &height);

    // Test tj3GetErrorCode
    tj3GetErrorCode(handle);

    // Clean up
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
