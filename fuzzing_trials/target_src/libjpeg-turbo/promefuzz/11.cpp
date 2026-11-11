// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3YUVPlaneWidth at turbojpeg.c:1057:15 in turbojpeg.h
// tjPlaneSizeYUV at turbojpeg.c:1048:25 in turbojpeg.h
// tj3YUVPlaneHeight at turbojpeg.c:1091:15 in turbojpeg.h
// tj3YUVPlaneSize at turbojpeg.c:1020:18 in turbojpeg.h
// tjPlaneHeight at turbojpeg.c:1117:15 in turbojpeg.h
// tjPlaneWidth at turbojpeg.c:1083:15 in turbojpeg.h
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
#include <iostream>

static void fuzz_tj3YUVPlaneWidth(int componentID, int width, int subsamp) {
    try {
        int result = tj3YUVPlaneWidth(componentID, width, subsamp);
        std::cout << "tj3YUVPlaneWidth: " << result << std::endl;
    } catch (...) {
        std::cerr << "Exception in tj3YUVPlaneWidth" << std::endl;
    }
}

static void fuzz_tjPlaneSizeYUV(int componentID, int width, int stride, int height, int subsamp) {
    try {
        unsigned long result = tjPlaneSizeYUV(componentID, width, stride, height, subsamp);
        std::cout << "tjPlaneSizeYUV: " << result << std::endl;
    } catch (...) {
        std::cerr << "Exception in tjPlaneSizeYUV" << std::endl;
    }
}

static void fuzz_tj3YUVPlaneHeight(int componentID, int height, int subsamp) {
    try {
        int result = tj3YUVPlaneHeight(componentID, height, subsamp);
        std::cout << "tj3YUVPlaneHeight: " << result << std::endl;
    } catch (...) {
        std::cerr << "Exception in tj3YUVPlaneHeight" << std::endl;
    }
}

static void fuzz_tj3YUVPlaneSize(int componentID, int width, int stride, int height, int subsamp) {
    try {
        size_t result = tj3YUVPlaneSize(componentID, width, stride, height, subsamp);
        std::cout << "tj3YUVPlaneSize: " << result << std::endl;
    } catch (...) {
        std::cerr << "Exception in tj3YUVPlaneSize" << std::endl;
    }
}

static void fuzz_tjPlaneHeight(int componentID, int height, int subsamp) {
    try {
        int result = tjPlaneHeight(componentID, height, subsamp);
        std::cout << "tjPlaneHeight: " << result << std::endl;
    } catch (...) {
        std::cerr << "Exception in tjPlaneHeight" << std::endl;
    }
}

static void fuzz_tjPlaneWidth(int componentID, int width, int subsamp) {
    try {
        int result = tjPlaneWidth(componentID, width, subsamp);
        std::cout << "tjPlaneWidth: " << result << std::endl;
    } catch (...) {
        std::cerr << "Exception in tjPlaneWidth" << std::endl;
    }
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 5) return 0;

    int componentID = Data[0] % 3; // 0 = Y, 1 = U/Cb, 2 = V/Cr
    int width = Data[1];
    int stride = Data[2];
    int height = Data[3];
    int subsamp = Data[4] % 6; // Assuming 6 subsampling options

    fuzz_tj3YUVPlaneWidth(componentID, width, subsamp);
    fuzz_tjPlaneSizeYUV(componentID, width, stride, height, subsamp);
    fuzz_tj3YUVPlaneHeight(componentID, height, subsamp);
    fuzz_tj3YUVPlaneSize(componentID, width, stride, height, subsamp);
    fuzz_tjPlaneHeight(componentID, height, subsamp);
    fuzz_tjPlaneWidth(componentID, width, subsamp);

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    