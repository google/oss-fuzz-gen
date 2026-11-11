// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Decompress16 at turbojpeg-mp.c:148:15 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
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
#include <exception>

static void handle_error(tjhandle handle) {
    char *errorStr = tj3GetErrorStr(handle);
    if (errorStr != nullptr) {
        fprintf(stderr, "Error: %s\n", errorStr);
    }
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(tjscalingfactor) + sizeof(tjregion) * 2) {
        return 0;
    }

    tjhandle handle = nullptr;
    void *buffer1 = nullptr;
    void *buffer2 = nullptr;
    unsigned short *dstBuf = nullptr;

    try {
        // Initialize TurboJPEG handle
        handle = tj3Init(TJINIT_DECOMPRESS);
        if (!handle) {
            handle_error(handle);
            return 0;
        }

        // Set Scaling Factor
        tjscalingfactor scalingFactor;
        memcpy(&scalingFactor, Data, sizeof(tjscalingfactor));
        if (tj3SetScalingFactor(handle, scalingFactor) == -1) {
            handle_error(handle);
        }

        // Set Cropping Region
        tjregion croppingRegion1, croppingRegion2;
        memcpy(&croppingRegion1, Data + sizeof(tjscalingfactor), sizeof(tjregion));
        memcpy(&croppingRegion2, Data + sizeof(tjscalingfactor) + sizeof(tjregion), sizeof(tjregion));

        if (tj3SetCroppingRegion(handle, croppingRegion1) == -1) {
            handle_error(handle);
        }

        if (tj3SetCroppingRegion(handle, croppingRegion2) == -1) {
            handle_error(handle);
        }

        // Allocate memory
        size_t bytesToAllocate = Size - (sizeof(tjscalingfactor) + sizeof(tjregion) * 2);
        buffer1 = tj3Alloc(bytesToAllocate);
        if (!buffer1) {
            handle_error(handle);
        }

        // Get error string
        handle_error(handle);

        // Decompress
        if (Size > sizeof(tjscalingfactor) + sizeof(tjregion) * 2) {
            dstBuf = new unsigned short[bytesToAllocate / sizeof(unsigned short)];
            if (tj3Decompress16(handle, Data, Size, dstBuf, 0, TJPF_RGB) == -1) {
                handle_error(handle);
            }
        }

        // Get error string
        handle_error(handle);

        // Free allocated memory
        tj3Free(buffer1);
        buffer1 = nullptr;

        // Allocate another buffer and free it
        buffer2 = tj3Alloc(bytesToAllocate);
        if (buffer2) {
            tj3Free(buffer2);
            buffer2 = nullptr;
        }

        // Destroy TurboJPEG handle
        tj3Destroy(handle);
        handle = nullptr;

    } catch (const std::exception &e) {
        fprintf(stderr, "Exception: %s\n", e.what());
    }

    // Cleanup
    if (buffer1) tj3Free(buffer1);
    if (buffer2) tj3Free(buffer2);
    if (dstBuf) delete[] dstBuf;
    if (handle) tj3Destroy(handle);

    return 0;
}