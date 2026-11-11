// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjPlaneHeight at turbojpeg.c:1117:15 in turbojpeg.h
// tj3YUVPlaneHeight at turbojpeg.c:1091:15 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tjPlaneWidth at turbojpeg.c:1083:15 in turbojpeg.h
// tj3YUVPlaneSize at turbojpeg.c:1020:18 in turbojpeg.h
// tj3YUVPlaneWidth at turbojpeg.c:1057:15 in turbojpeg.h
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
#include <cstddef>
#include <iostream>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 5) return 0; // Ensure enough data is available

    int componentID = Data[0] % 3; // Assuming componentID is 0, 1, or 2
    int height = Data[1];
    int width = Data[2];
    int stride = Data[3];
    int subsamp = Data[4] % 4; // Assuming subsamp is one of the valid subsampling options

    try {
        // Invoke tjPlaneHeight
        int planeHeight = tjPlaneHeight(componentID, height, subsamp);
        if (planeHeight == -1) std::cerr << "Error in tjPlaneHeight\n";

        // Invoke tj3YUVPlaneHeight
        int yuvPlaneHeight = tj3YUVPlaneHeight(componentID, height, subsamp);
        if (yuvPlaneHeight == 0) std::cerr << "Invalid arguments in tj3YUVPlaneHeight\n";

        // Invoke tjPlaneSizeYUV
        unsigned long planeSizeYUV = tjPlaneSizeYUV(componentID, width, stride, height, subsamp);
        if (planeSizeYUV == (unsigned long)-1) std::cerr << "Error in tjPlaneSizeYUV\n";

        // Invoke tjPlaneWidth
        int planeWidth = tjPlaneWidth(componentID, width, subsamp);
        if (planeWidth == -1) std::cerr << "Error in tjPlaneWidth\n";

        // Invoke tj3YUVPlaneSize
        size_t yuvPlaneSize = tj3YUVPlaneSize(componentID, width, stride, height, subsamp);
        if (yuvPlaneSize == 0) std::cerr << "Invalid arguments in tj3YUVPlaneSize\n";

        // Invoke tj3YUVPlaneWidth
        int yuvPlaneWidth = tj3YUVPlaneWidth(componentID, width, subsamp);
        if (yuvPlaneWidth == 0) std::cerr << "Invalid arguments in tj3YUVPlaneWidth\n";

    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}