// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitTransform at turbojpeg.c:2751:20 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjDecompressHeader at turbojpeg.c:1914:15 in turbojpeg.h
// tjBufSizeYUV2 at turbojpeg.c:999:25 in turbojpeg.h
// tjDecompressToYUVPlanes at turbojpeg.c:2291:15 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tjDecompressToYUV at turbojpeg.c:2452:15 in turbojpeg.h
// tj3DecompressToYUVPlanes8 at turbojpeg.c:2125:15 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
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
#include <cstdio>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize tjhandle for transformation
    tjhandle transformHandle = tjInitTransform();
    if (!transformHandle) return 0;

    // Initialize tjhandle for decompression
    tjhandle decompressHandle = tjInitDecompress();
    if (!decompressHandle) {
        tjDestroy(transformHandle);
        return 0;
    }

    // Prepare dummy file
    writeDummyFile(Data, Size);

    // Decompress to YUV planes
    unsigned char *yuvPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};
    int width = 0, height = 0;
    tjDecompressHeader(decompressHandle, const_cast<unsigned char*>(Data), Size, &width, &height);

    size_t planeSize = tjBufSizeYUV2(width, 4, height, TJSAMP_420);
    for (int i = 0; i < 3; i++) {
        yuvPlanes[i] = static_cast<unsigned char *>(malloc(planeSize));
    }

    tjDecompressToYUVPlanes(decompressHandle, const_cast<unsigned char*>(Data), Size, yuvPlanes, width, strides, height, 0);

    // Compress to JPEG
    unsigned long compressedSize = tjBufSize(width, height, TJSAMP_420);
    unsigned char *compressedBuf = static_cast<unsigned char *>(malloc(compressedSize));
    tjCompress(transformHandle, yuvPlanes[0], width, 0, height, 3, compressedBuf, &compressedSize, TJSAMP_420, 75, 0);

    // Decompress to YUV
    unsigned char *yuvBuf = static_cast<unsigned char *>(malloc(planeSize));
    tjDecompressToYUV(decompressHandle, const_cast<unsigned char*>(Data), Size, yuvBuf, 0);

    // Decompress to YUVPlanes8
    tj3DecompressToYUVPlanes8(decompressHandle, const_cast<unsigned char*>(Data), Size, yuvPlanes, strides);

    // Decompress to RGB
    int pixelFormat = TJPF_RGB;
    unsigned char *rgbBuf = static_cast<unsigned char *>(malloc(width * height * tjPixelSize[pixelFormat]));
    tjDecompress2(decompressHandle, const_cast<unsigned char*>(Data), Size, rgbBuf, width, 0, height, pixelFormat, 0);

    // Cleanup
    for (int i = 0; i < 3; i++) {
        free(yuvPlanes[i]);
    }
    free(compressedBuf);
    free(yuvBuf);
    free(rgbBuf);

    tjDestroy(decompressHandle);
    tjDestroy(transformHandle);

    return 0;
}