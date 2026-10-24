// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompressHeader3 at turbojpeg.c:1874:15 in turbojpeg.h
// tj3GetICCProfile at turbojpeg.c:1926:15 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3DecompressHeader at turbojpeg.c:1815:15 in turbojpeg.h
// tjDecompressHeader at turbojpeg.c:1914:15 in turbojpeg.h
// tj3DecompressToYUVPlanes8 at turbojpeg.c:2125:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
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
#include <iostream>

static void handleError(tjhandle handle) {
    int errorCode = tj3GetErrorCode(handle);
    if (errorCode == TJERR_FATAL) {
        std::cerr << "Fatal error occurred: " << tj3GetErrorStr(handle) << std::endl;
    } else if (errorCode == TJERR_WARNING) {
        std::cerr << "Warning: " << tj3GetErrorStr(handle) << std::endl;
    }
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tjInitDecompress();
    if (!handle) {
        std::cerr << "Failed to initialize TurboJPEG decompressor." << std::endl;
        return 0;
    }

    // Prepare variables for tjDecompressHeader3
    int width, height, subsamp, colorspace;
    if (tjDecompressHeader3(handle, Data, Size, &width, &height, &subsamp, &colorspace) == 0) {
        // Successfully retrieved header
    } else {
        handleError(handle);
    }

    // Prepare variables for tj3GetICCProfile
    unsigned char *iccBuf = nullptr;
    size_t iccSize = 0;
    if (tj3GetICCProfile(handle, &iccBuf, &iccSize) == 0) {
        if (iccBuf) tj3Free(iccBuf);
    } else {
        handleError(handle);
    }

    // Prepare variables for tj3DecompressHeader
    if (tj3DecompressHeader(handle, Data, Size) == 0) {
        // Successfully retrieved header
    } else {
        handleError(handle);
    }

    // Prepare variables for tjDecompressHeader
    if (tjDecompressHeader(handle, const_cast<unsigned char*>(Data), Size, &width, &height) == 0) {
        // Successfully retrieved header
    } else {
        handleError(handle);
    }

    // Prepare variables for tj3DecompressToYUVPlanes8
    unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};
    if (tj3DecompressToYUVPlanes8(handle, Data, Size, dstPlanes, strides) == 0) {
        // Successfully decompressed to YUV planes
    } else {
        handleError(handle);
    }

    tjDestroy(handle);
    return 0;
}