// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3GetScalingFactors at turbojpeg.c:1959:28 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tjDecompressToYUVPlanes at turbojpeg.c:2291:15 in turbojpeg.h
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
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
#include <cstdlib>
#include <cstring>
#include <cstdio>

static void fuzz_tj3Init(int initType) {
    tjhandle handle = tj3Init(initType);
    if (handle) {
        tj3Destroy(handle);
    }
}

static void fuzz_tj3SetCroppingRegion(tjhandle handle, tjregion croppingRegion) {
    tj3SetCroppingRegion(handle, croppingRegion);
}

static void fuzz_tj3GetScalingFactors() {
    int numScalingFactors = 0;
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(&numScalingFactors);
    if (scalingFactors) {
        // Normally, you'd do something with the scaling factors here
    }
}

static void fuzz_tj3SetScalingFactor(tjhandle handle, tjscalingfactor scalingFactor) {
    tj3SetScalingFactor(handle, scalingFactor);
}

static void fuzz_tjDecompressToYUVPlanes(tjhandle handle, const uint8_t *jpegBuf, unsigned long jpegSize) {
    int width = 0, height = 0;
    unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};
    tjDecompressToYUVPlanes(handle, jpegBuf, jpegSize, dstPlanes, width, strides, height, 0);
}

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int initType;
    memcpy(&initType, Data, sizeof(int));

    tjhandle handle = tj3Init(initType);
    if (!handle) return 0;

    // Fuzz tj3SetCroppingRegion
    if (Size >= sizeof(int) + sizeof(tjregion)) {
        tjregion region;
        memcpy(&region, Data + sizeof(int), sizeof(tjregion));
        fuzz_tj3SetCroppingRegion(handle, region);
    }

    // Fuzz tj3GetScalingFactors
    fuzz_tj3GetScalingFactors();

    // Fuzz tj3SetScalingFactor
    if (Size >= sizeof(int) + sizeof(tjscalingfactor)) {
        tjscalingfactor scalingFactor;
        memcpy(&scalingFactor, Data + sizeof(int), sizeof(tjscalingfactor));
        fuzz_tj3SetScalingFactor(handle, scalingFactor);
    }

    // Fuzz tjDecompressToYUVPlanes
    if (Size > sizeof(int)) {
        fuzz_tjDecompressToYUVPlanes(handle, Data + sizeof(int), Size - sizeof(int));
    }

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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    