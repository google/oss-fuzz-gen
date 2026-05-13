#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include "../src/turbojpeg.h"
#include <iostream>
#include <cstring>

static void fuzz_tj3YUVPlaneWidth(const uint8_t *Data, size_t Size) {
    if (Size < 3 * sizeof(int)) return;

    int componentID = *(reinterpret_cast<const int*>(Data));
    int width = *(reinterpret_cast<const int*>(Data + sizeof(int)));
    int subsamp = *(reinterpret_cast<const int*>(Data + 2 * sizeof(int)));

    int result = tj3YUVPlaneWidth(componentID, width, subsamp);
    (void)result; // Use the result to avoid unused variable warning
}

static void fuzz_tj3DecodeYUV8(const uint8_t *Data, size_t Size) {
    if (Size < 4 * sizeof(int) + 2 * sizeof(uintptr_t)) return;

    tjhandle handle = nullptr; // Normally, you would initialize this properly
    const unsigned char *srcBuf = reinterpret_cast<const unsigned char*>(Data);
    int align = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t)));
    unsigned char *dstBuf = new unsigned char[Size];
    int width = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + sizeof(int)));
    int pitch = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 2 * sizeof(int)));
    int height = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 3 * sizeof(int)));
    int pixelFormat = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 4 * sizeof(int)));

    int result = tj3DecodeYUV8(handle, srcBuf, align, dstBuf, width, pitch, height, pixelFormat);
    (void)result; 

    delete[] dstBuf;
}

static void fuzz_tjEncodeYUV(const uint8_t *Data, size_t Size) {
    if (Size < 5 * sizeof(int) + 2 * sizeof(uintptr_t)) return;

    tjhandle handle = nullptr; // Normally, you would initialize this properly
    unsigned char *srcBuf = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(Data));
    int width = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t)));
    int pitch = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + sizeof(int)));
    int height = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 2 * sizeof(int)));
    int pixelSize = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 3 * sizeof(int)));
    unsigned char *dstBuf = new unsigned char[Size];
    int subsamp = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 4 * sizeof(int)));
    int flags = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 5 * sizeof(int)));

    int result = tjEncodeYUV(handle, srcBuf, width, pitch, height, pixelSize, dstBuf, subsamp, flags);
    (void)result;

    delete[] dstBuf;
}

static void fuzz_tjEncodeYUV2(const uint8_t *Data, size_t Size) {
    if (Size < 5 * sizeof(int) + 2 * sizeof(uintptr_t)) return;

    tjhandle handle = nullptr; // Normally, you would initialize this properly
    unsigned char *srcBuf = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(Data));
    int width = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t)));
    int pitch = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + sizeof(int)));
    int height = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 2 * sizeof(int)));
    int pixelFormat = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 3 * sizeof(int)));
    unsigned char *dstBuf = new unsigned char[Size];
    int subsamp = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 4 * sizeof(int)));
    int flags = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 5 * sizeof(int)));

    int result = tjEncodeYUV2(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, subsamp, flags);
    (void)result;

    delete[] dstBuf;
}

static void fuzz_tjDecodeYUV(const uint8_t *Data, size_t Size) {
    if (Size < 6 * sizeof(int) + 2 * sizeof(uintptr_t)) return;

    tjhandle handle = nullptr; // Normally, you would initialize this properly
    const unsigned char *srcBuf = reinterpret_cast<const unsigned char*>(Data);
    int align = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t)));
    int subsamp = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + sizeof(int)));
    unsigned char *dstBuf = new unsigned char[Size];
    int width = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 2 * sizeof(int)));
    int pitch = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 3 * sizeof(int)));
    int height = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 4 * sizeof(int)));
    int pixelFormat = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 5 * sizeof(int)));
    int flags = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 6 * sizeof(int)));

    int result = tjDecodeYUV(handle, srcBuf, align, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);
    (void)result;

    delete[] dstBuf;
}

static void fuzz_tjDecodeYUVPlanes(const uint8_t *Data, size_t Size) {
    if (Size < 6 * sizeof(int) + 3 * sizeof(uintptr_t)) return;

    tjhandle handle = nullptr; // Normally, you would initialize this properly
    const unsigned char *srcPlanes[3] = {
        reinterpret_cast<const unsigned char*>(Data),
        reinterpret_cast<const unsigned char*>(Data + Size / 3),
        reinterpret_cast<const unsigned char*>(Data + 2 * Size / 3)
    };
    const int strides[3] = { *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t))),
                             *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + sizeof(int))),
                             *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 2 * sizeof(int))) };
    int subsamp = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 3 * sizeof(int)));
    unsigned char *dstBuf = new unsigned char[Size];
    int width = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 4 * sizeof(int)));
    int pitch = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 5 * sizeof(int)));
    int height = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 6 * sizeof(int)));
    int pixelFormat = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 7 * sizeof(int)));
    int flags = *(reinterpret_cast<const int*>(Data + sizeof(uintptr_t) + 8 * sizeof(int)));

    int result = tjDecodeYUVPlanes(handle, srcPlanes, strides, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);
    (void)result;

    delete[] dstBuf;
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    fuzz_tj3YUVPlaneWidth(Data, Size);
    fuzz_tj3DecodeYUV8(Data, Size);
    fuzz_tjEncodeYUV(Data, Size);
    fuzz_tjEncodeYUV2(Data, Size);
    fuzz_tjDecodeYUV(Data, Size);
    fuzz_tjDecodeYUVPlanes(Data, Size);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
