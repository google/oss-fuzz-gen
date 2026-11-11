// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3TransformBufSize at turbojpeg.c:2831:18 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Transform at turbojpeg.c:2870:15 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Transform at turbojpeg.c:2870:15 in turbojpeg.h
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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tj3Init(TJINIT_TRANSFORM);
    if (!handle) return 0;

    // Prepare transformation parameters
    tjtransform transform = {};
    transform.op = Data[0] % 8; // Random operation from 0 to 7

    // Estimate buffer size
    size_t bufSize = tj3TransformBufSize(handle, &transform);
    if (bufSize == 0) {
        tj3Destroy(handle);
        return 0;
    }

    // Allocate buffer
    unsigned char *dstBuf = static_cast<unsigned char*>(tj3Alloc(bufSize));
    if (!dstBuf) {
        tj3Destroy(handle);
        return 0;
    }

    // Prepare destination sizes array
    size_t dstSizes[1] = { bufSize };

    // Perform transformation
    unsigned char *dstBufs[1] = { dstBuf };
    int result = tj3Transform(handle, Data, Size, 1, dstBufs, dstSizes, &transform);
    if (result == -1) {
        tj3Free(dstBuf);
        tj3Destroy(handle);
        return 0;
    }

    // Get error string
    char *errorStr = tj3GetErrorStr(handle);

    // Free the destination buffer
    tj3Free(dstBuf);

    // Set a parameter
    result = tj3Set(handle, TJPARAM_NOREALLOC, 1);
    if (result == -1) {
        tj3Destroy(handle);
        return 0;
    }

    // Perform transformation again
    result = tj3Transform(handle, Data, Size, 1, dstBufs, dstSizes, &transform);
    if (result == -1) {
        errorStr = tj3GetErrorStr(handle);
    }

    // Free the destination buffer again
    tj3Free(dstBuf);

    // Destroy the TurboJPEG instance
    tj3Destroy(handle);

    return 0;
}