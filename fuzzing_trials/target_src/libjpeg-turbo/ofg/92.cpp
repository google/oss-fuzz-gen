#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    if (size < 12) {
        // Not enough data to proceed
        return 0;
    }

    // Initialize the TurboJPEG compressor
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Prepare input data
    unsigned char *srcBuf = const_cast<unsigned char *>(data);
    int width = 2 + (data[0] % 256);  // Ensure at least 2 pixels wide
    int height = 2 + (data[1] % 256); // Ensure at least 2 pixels high
    int pitch = width * 3;            // Assuming RGB input
    int pixelFormat = TJPF_RGB;

    // Ensure the input buffer has enough data for the specified width and height
    if (size < static_cast<size_t>(pitch * height)) {
        tjDestroy(handle);
        return 0;
    }

    // Prepare output buffer
    int yuvSize = tjBufSizeYUV2(width, 4, height, TJSAMP_420);
    unsigned char *dstBuf = (unsigned char *)malloc(yuvSize);
    if (!dstBuf) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjEncodeYUV(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, 4, TJSAMP_420);
    if (result != 0) {
        // Handle the error if needed
        free(dstBuf);
        tjDestroy(handle);
        return 0;
    }

    // Ensure the output buffer is used meaningfully
    // For example, you might check the first few bytes to ensure they are not all zero
    if (yuvSize > 0 && dstBuf[0] == 0 && dstBuf[1] == 0 && dstBuf[2] == 0) {
        // If the output buffer is all zero, it might indicate an issue
    }

    // Additional check to ensure the function is exercised
    // This is a simple heuristic to ensure some variation in output
    if (yuvSize > 0 && (dstBuf[0] != 0 || dstBuf[1] != 0 || dstBuf[2] != 0)) {
        // Output buffer has non-zero data, indicating some processing occurred
    }

    // Clean up
    free(dstBuf);
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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
