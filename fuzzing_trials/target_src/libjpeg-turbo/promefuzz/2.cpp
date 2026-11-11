// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3DecompressToYUV8 at turbojpeg.c:2341:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Alloc at turbojpeg.c:877:17 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3DecodeYUV8 at turbojpeg.c:2678:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Step 1: Prepare environment
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    const int width = 128;  // Arbitrary width
    const int height = 128; // Arbitrary height
    const int subsamp = TJSAMP_444;
    const int align = 4;    // Row alignment

    // Calculate buffer size
    size_t yuvBufSize = tj3YUVBufSize(width, align, height, subsamp);
    if (yuvBufSize == 0) {
        tj3Destroy(handle);
        return 0;
    }

    // Allocate buffers
    unsigned char *yuvBuf = static_cast<unsigned char *>(tj3Alloc(yuvBufSize));
    if (!yuvBuf) {
        tj3Destroy(handle);
        return 0;
    }
    unsigned char *jpegBuf = static_cast<unsigned char *>(tj3Alloc(Size));
    if (!jpegBuf) {
        tj3Free(yuvBuf);
        tj3Destroy(handle);
        return 0;
    }
    memcpy(jpegBuf, Data, Size);

    // Step 2: Invoke target functions
    int result = tj3DecompressToYUV8(handle, jpegBuf, Size, yuvBuf, align);
    if (result != 0) {
        tj3GetErrorStr(handle);
    }

    unsigned char *decodedBuf = static_cast<unsigned char *>(tj3Alloc(width * height * 3));
    if (!decodedBuf) {
        tj3Free(jpegBuf);
        tj3Free(yuvBuf);
        tj3Destroy(handle);
        return 0;
    }

    result = tj3DecodeYUV8(handle, yuvBuf, align, decodedBuf, width, width * 3, height, TJPF_RGB);
    if (result != 0) {
        tj3GetErrorStr(handle);
    }

    // Step 3: Cleanup
    tj3Free(decodedBuf);
    tj3Free(jpegBuf);
    tj3Free(yuvBuf);
    tj3Destroy(handle);

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    