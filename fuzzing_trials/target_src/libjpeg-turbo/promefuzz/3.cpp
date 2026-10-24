// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Decompress16 at turbojpeg-mp.c:148:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <turbojpeg.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void writeDummyFile(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(tjscalingfactor) + sizeof(tjregion) + 2 * sizeof(size_t)) {
        return 0;
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    // Set Scaling Factor
    tjscalingfactor scalingFactor = *reinterpret_cast<const tjscalingfactor *>(Data);
    Data += sizeof(tjscalingfactor);
    Size -= sizeof(tjscalingfactor);

    tj3SetScalingFactor(handle, scalingFactor);

    // Set Cropping Region
    tjregion croppingRegion = *reinterpret_cast<const tjregion *>(Data);
    Data += sizeof(tjregion);
    Size -= sizeof(tjregion);

    tj3SetCroppingRegion(handle, croppingRegion);

    // Allocate memory
    size_t allocSize = *reinterpret_cast<const size_t *>(Data);
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    void *buffer1 = tj3Alloc(allocSize);

    // Get Error String
    char *errorStr1 = tj3GetErrorStr(handle);

    // Decompress JPEG
    if (Size >= sizeof(size_t)) {
        size_t jpegSize = *reinterpret_cast<const size_t *>(Data);
        Data += sizeof(size_t);
        Size -= sizeof(size_t);

        const unsigned char *jpegBuf = Data;
        unsigned short *dstBuf = (unsigned short *)malloc(allocSize);

        if (jpegSize <= Size && dstBuf) {
            tj3Decompress16(handle, jpegBuf, jpegSize, dstBuf, 0, TJPF_RGB);
        }

        free(dstBuf);
    }

    // Get another Error String
    char *errorStr2 = tj3GetErrorStr(handle);

    // Free allocated memory
    tj3Free(buffer1);

    // Destroy TurboJPEG handle
    tj3Destroy(handle);

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    