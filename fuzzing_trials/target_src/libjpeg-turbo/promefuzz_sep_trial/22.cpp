// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3GetScalingFactors at turbojpeg.c:1959:28 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tjDecompressToYUVPlanes at turbojpeg.c:2291:15 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
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

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG handle for decompression
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (!handle) return 0;

    // Get scaling factors
    int numScalingFactors = 0;
    tjscalingfactor *scalingFactors = tj3GetScalingFactors(&numScalingFactors);

    if (scalingFactors && numScalingFactors > 0) {
        // Set a scaling factor
        tj3SetScalingFactor(handle, scalingFactors[0]);
    }

    // Prepare dummy JPEG data
    unsigned long jpegSize = Size;
    unsigned char *jpegBuf = const_cast<unsigned char *>(Data);

    // Prepare destination buffers for YUV planes
    int width = 128; // Arbitrary width
    int height = 128; // Arbitrary height
    unsigned char *dstPlanes[3];
    int strides[3] = {width, width / 2, width / 2}; // Example strides for YUV

    for (int i = 0; i < 3; i++) {
        dstPlanes[i] = static_cast<unsigned char *>(malloc(strides[i] * height / (i == 0 ? 1 : 2)));
        if (!dstPlanes[i]) {
            tj3Destroy(handle);
            return 0;
        }
    }

    // Decompress to YUV planes
    tjDecompressToYUVPlanes(handle, jpegBuf, jpegSize, dstPlanes, width, strides, height, 0);

    // Clean up
    for (int i = 0; i < 3; i++) {
        free(dstPlanes[i]);
    }
    tj3Destroy(handle);

    // Compress using tjCompress
    tjhandle compressHandle = tj3Init(TJINIT_COMPRESS);
    if (compressHandle) {
        unsigned char *compressedBuf = nullptr;
        unsigned long compressedSize = 0;
        tjCompress(compressHandle, jpegBuf, width, 0, height, 3, compressedBuf, &compressedSize, TJSAMP_444, 75, 0);
        tj3Destroy(compressHandle);
    }

    return 0;
}