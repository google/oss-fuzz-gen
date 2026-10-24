// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tjDecompressHeader2 at turbojpeg.c:1903:15 in turbojpeg.h
// tjDecompressHeader3 at turbojpeg.c:1874:15 in turbojpeg.h
// tj3DecompressHeader at turbojpeg.c:1815:15 in turbojpeg.h
// tj3GetICCProfile at turbojpeg.c:1926:15 in turbojpeg.h
// tj3Free at turbojpeg.c:890:16 in turbojpeg.h
// tjDecompressHeader at turbojpeg.c:1914:15 in turbojpeg.h
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
#include <cstdio>
#include <cstring>

static void handleError(tjhandle handle) {
    int errorCode = tj3GetErrorCode(handle);
    if (errorCode == TJERR_FATAL) {
        fprintf(stderr, "Fatal error: %s\n", tj3GetErrorStr(handle));
    } else if (errorCode == TJERR_WARNING) {
        fprintf(stderr, "Warning: %s\n", tj3GetErrorStr(handle));
    }
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    tjhandle handle = tjInitDecompress();
    if (!handle) {
        fprintf(stderr, "Failed to initialize TurboJPEG decompressor\n");
        return 0;
    }

    int width = 0, height = 0, subsamp = 0, colorspace = 0;
    unsigned char *iccBuf = nullptr;
    size_t iccSize = 0;

    // Test tjDecompressHeader2
    if (tjDecompressHeader2(handle, const_cast<unsigned char*>(Data), Size,
                            &width, &height, &subsamp) == -1) {
        handleError(handle);
    }

    // Test tjDecompressHeader3
    if (tjDecompressHeader3(handle, Data, Size, &width, &height, &subsamp, &colorspace) == -1) {
        handleError(handle);
    }

    // Test tj3DecompressHeader
    if (tj3DecompressHeader(handle, Data, Size) == -1) {
        handleError(handle);
    }

    // Test tj3GetICCProfile
    if (tj3GetICCProfile(handle, &iccBuf, &iccSize) == -1) {
        handleError(handle);
    } else if (iccBuf) {
        tj3Free(iccBuf);
    }

    // Test tjDecompressHeader
    if (tjDecompressHeader(handle, const_cast<unsigned char*>(Data), Size, &width, &height) == -1) {
        handleError(handle);
    }

    tjDestroy(handle);
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    