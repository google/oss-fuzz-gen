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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

static tjhandle createDecompressor() {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        std::cerr << "Failed to initialize decompressor: " << tjGetErrorStr() << std::endl;
    }
    return handle;
}

static void destroyDecompressor(tjhandle handle) {
    if (handle) {
        tjDestroy(handle);
    }
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    tjhandle handle = createDecompressor();
    if (!handle) return 0;

    // Attempt to set a scaling factor
    tjscalingfactor scalingFactor = { 1, 1 };
    tj3SetScalingFactor(handle, scalingFactor);

    // Attempt to set a cropping region
    tjregion croppingRegion = { 0, 0, 1, 1 };
    tj3SetCroppingRegion(handle, croppingRegion);

    // Attempt to get a parameter
    int param = *reinterpret_cast<const int*>(Data);
    tj3Get(handle, param);

    // Attempt to set a parameter
    tj3Set(handle, param, 1);

    // Check error codes
    tj3GetErrorCode(handle);
    tjGetErrorCode(handle);

    destroyDecompressor(handle);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
