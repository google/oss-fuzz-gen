// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjBufSizeYUV at turbojpeg.c:1007:25 in turbojpeg.h
// TJBUFSIZEYUV at turbojpeg.c:1013:25 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tj3YUVPlaneSize at turbojpeg.c:1020:18 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 5) return 0;

    int width, height, align, subsamp, componentID, stride, jpegSubsamp;

    memcpy(&width, Data, sizeof(int));
    memcpy(&height, Data + sizeof(int), sizeof(int));
    memcpy(&align, Data + 2 * sizeof(int), sizeof(int));
    memcpy(&subsamp, Data + 3 * sizeof(int), sizeof(int));
    memcpy(&componentID, Data + 4 * sizeof(int), sizeof(int));

    if (Size >= 6 * sizeof(int)) {
        stride = *reinterpret_cast<const int*>(Data + 5 * sizeof(int));
    } else {
        stride = 0;
    }

    if (Size >= 7 * sizeof(int)) {
        jpegSubsamp = *reinterpret_cast<const int*>(Data + 6 * sizeof(int));
    } else {
        jpegSubsamp = subsamp;
    }

    // Call tjBufSizeYUV2
    unsigned long bufSizeYUV2 = tjBufSizeYUV2(width, align, height, subsamp);
    if (bufSizeYUV2 == -1) {
        std::cerr << "tjBufSizeYUV2 failed" << std::endl;
    }

    // Call tjBufSizeYUV
    unsigned long bufSizeYUV = tjBufSizeYUV(width, height, subsamp);
    if (bufSizeYUV == -1) {
        std::cerr << "tjBufSizeYUV failed" << std::endl;
    }

    // Call TJBUFSIZEYUV
    unsigned long bufSizeYUVSimple = TJBUFSIZEYUV(width, height, jpegSubsamp);
    if (bufSizeYUVSimple == -1) {
        std::cerr << "TJBUFSIZEYUV failed" << std::endl;
    }

    // Call tjPlaneSizeYUV
    unsigned long planeSizeYUV = tjPlaneSizeYUV(componentID, width, stride, height, subsamp);
    if (planeSizeYUV == -1) {
        std::cerr << "tjPlaneSizeYUV failed" << std::endl;
    }

    // Call tj3YUVPlaneSize
    size_t planeSizeYUV3 = tj3YUVPlaneSize(componentID, width, stride, height, subsamp);
    if (planeSizeYUV3 == 0) {
        std::cerr << "tj3YUVPlaneSize failed" << std::endl;
    }

    // Call tjBufSize
    unsigned long bufSize = tjBufSize(width, height, jpegSubsamp);
    if (bufSize == -1) {
        std::cerr << "tjBufSize failed" << std::endl;
    }

    return 0;
}