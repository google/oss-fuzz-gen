#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG handle
    tjhandle handle = tjInitTransform();
    if (handle == nullptr) {
        return 0;
    }

    // Ensure that the size is sufficient for a tjtransform structure
    if (size < sizeof(tjtransform)) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate a buffer for the transformed image
    unsigned long jpegSize = 0;
    unsigned char *jpegBuf = nullptr;

    // Cast the input data to a tjtransform structure
    tjtransform transform;
    memcpy(&transform, data, sizeof(tjtransform));

    // Use the remaining data as the JPEG buffer if possible
    const unsigned char *jpegData = data + sizeof(tjtransform);
    size_t jpegDataSize = size - sizeof(tjtransform);

    // Dummy source buffer and width/height for testing
    int width = 10, height = 10, jpegSubsamp = TJSAMP_444, jpegQual = 100;
    unsigned char *srcBuf = (unsigned char *)malloc(width * height * tjPixelSize[TJPF_RGB]);
    if (srcBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Fill the source buffer with some data to simulate a real image
    memset(srcBuf, 128, width * height * tjPixelSize[TJPF_RGB]);

    // Encode the dummy image to a JPEG buffer to ensure non-null input
    int encodeResult = tjCompress2(handle, srcBuf, width, 0, height, TJPF_RGB, &jpegBuf, &jpegSize, jpegSubsamp, jpegQual, TJFLAG_NOREALLOC);
    if (encodeResult != 0) {
        free(srcBuf);
        tjDestroy(handle);
        return 0;
    }

    // Use the actual input data as the JPEG buffer if it is large enough
    if (jpegDataSize > 0) {
        unsigned char *tempBuf = (unsigned char *)malloc(jpegDataSize);
        if (tempBuf != nullptr) {
            memcpy(tempBuf, jpegData, jpegDataSize);
            tjFree(jpegBuf);  // Free the previously allocated buffer
            jpegBuf = tempBuf;
            jpegSize = jpegDataSize;
        }
    }

    // Call the function-under-test
    int result = tjTransform(handle, jpegBuf, jpegSize, 1, &jpegBuf, &jpegSize, &transform, TJFLAG_NOREALLOC);

    // Clean up
    free(srcBuf);
    if (jpegBuf != nullptr) {
        tjFree(jpegBuf);
    }
    tjDestroy(handle);

    return result == 0 ? 1 : 0; // Return 1 if the transform was successful, 0 otherwise
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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
