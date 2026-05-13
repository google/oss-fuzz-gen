// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjDecompressHeader3 at turbojpeg.c:1874:15 in turbojpeg.h
// tjCompressFromYUVPlanes at turbojpeg.c:1394:15 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
// tjDecompress2 at turbojpeg.c:2059:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    // Variables for image properties
    int width = 0, height = 0, jpegSubsamp = -1, jpegColorspace = -1;
    unsigned long jpegSize = Size;
    unsigned char *jpegBuf = const_cast<unsigned char *>(Data);

    // Fuzz tjDecompressHeader2
    tjDecompressHeader2(handle, jpegBuf, jpegSize, &width, &height, &jpegSubsamp);

    // Fuzz tjDecompressHeader3
    tjDecompressHeader3(handle, jpegBuf, jpegSize, &width, &height, &jpegSubsamp, &jpegColorspace);

    // Prepare for tjCompressFromYUVPlanes
    const unsigned char *srcPlanes[3] = {jpegBuf, jpegBuf, jpegBuf};
    int strides[3] = {width, width / 2, width / 2};
    unsigned char *compressedBuf = nullptr;
    unsigned long compressedSize = 0;
    int jpegQual = 75;
    int flags = 0;

    // Fuzz tjCompressFromYUVPlanes
    tjCompressFromYUVPlanes(handle, srcPlanes, width, strides, height, jpegSubsamp, &compressedBuf, &compressedSize, jpegQual, flags);

    // Prepare for tjCompress
    unsigned char *dstBuf = (unsigned char *)malloc(Size);
    if (dstBuf) {
        int pixelSize = 3; // Assume RGB
        tjCompress(handle, jpegBuf, width, width * pixelSize, height, pixelSize, dstBuf, &compressedSize, jpegSubsamp, jpegQual, flags);
        free(dstBuf);
    }

    // Check for errors
    int errorCode = tj3GetErrorCode(handle);

    // Prepare for tjDecompress2
    unsigned char *decompressedBuf = (unsigned char *)malloc(width * height * 3);
    if (decompressedBuf) {
        int pixelFormat = TJPF_RGB;
        tjDecompress2(handle, jpegBuf, jpegSize, decompressedBuf, width, width * 3, height, pixelFormat, flags);
        free(decompressedBuf);
    }

    // Cleanup
    tjDestroy(handle);
    tjFree(compressedBuf);

    return 0;
}