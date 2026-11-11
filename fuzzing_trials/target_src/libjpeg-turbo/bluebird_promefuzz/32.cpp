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
#include <cstdio>
#include "../src/turbojpeg.h"

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a TurboJPEG handle for transformation
    tjhandle handle = tjInitTransform();
    if (!handle) {
        return 0; // Initialization failed, nothing to fuzz here
    }

    // Fuzz tj3GetErrorStr with both a valid handle and NULL
    tj3GetErrorStr(handle);
    tj3GetErrorStr(NULL);

    // Prepare variables for tjDecompressHeader3
    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;
    if (tjDecompressHeader3(handle, Data, Size, &width, &height, &jpegSubsamp, &jpegColorspace) == 0) {
        // Fuzz tj3Get with some parameter values
        tj3Get(handle, TJPARAM_QUALITY);
        tj3Get(handle, TJPARAM_SUBSAMP);

        // Fuzz tj3GetICCProfile
        unsigned char *iccBuf = NULL;
        size_t iccSize = 0;
        tj3GetICCProfile(handle, &iccBuf, &iccSize);
        if (iccBuf) {
            tj3Free(iccBuf); // Free the ICC buffer if it was allocated
        }
    }

    // Fuzz tj3SetICCProfile with various conditions
    tj3SetICCProfile(handle, const_cast<uint8_t*>(Data), Size);
    tj3SetICCProfile(handle, NULL, 0);

    // Cleanup the TurboJPEG handle
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
