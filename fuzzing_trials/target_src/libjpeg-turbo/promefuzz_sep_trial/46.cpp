// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjGetScalingFactors at turbojpeg.c:1974:28 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tjDecompressToYUVPlanes at turbojpeg.c:2291:15 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a TurboJPEG decompression instance
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (!handle) return 0;

    // Variables for image properties
    int width = 0, height = 0, jpegSubsamp = 0;

    // Try to read the JPEG header
    if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size, &width, &height, &jpegSubsamp) == 0) {
        // Get scaling factors
        int numScalingFactors = 0;
        tjscalingfactor *scalingFactors = tjGetScalingFactors(&numScalingFactors);

        if (scalingFactors && numScalingFactors > 0) {
            // Set a random scaling factor
            tj3SetScalingFactor(handle, scalingFactors[0]);

            // Prepare destination buffers
            unsigned char *dstPlanes[3];
            int strides[3] = { width, width / 2, width / 2 };
            for (int i = 0; i < 3; i++) {
                dstPlanes[i] = (unsigned char*)malloc(strides[i] * height);
                if (!dstPlanes[i]) goto cleanup;
            }

            // Decompress to YUV planes
            tjDecompressToYUVPlanes(handle, Data, Size, dstPlanes, width, strides, height, 0);

            // Free the destination buffers
            for (int i = 0; i < 3; i++) {
                free(dstPlanes[i]);
            }
        }
    }

cleanup:
    // Destroy the TurboJPEG instance
    tj3Destroy(handle);

    return 0;
}