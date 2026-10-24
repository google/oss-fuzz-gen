#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data size is large enough to simulate a valid image
    if (size < sizeof(uint16_t) * 3) {  // Assuming J16SAMPLE is a 16-bit integer
        tjDestroy(handle);
        return 0;
    }

    // Initialize input parameters
    const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data); // Assuming J16SAMPLE is a 16-bit integer
    int width = 2;  // Minimal width for testing
    int height = 2; // Minimal height for testing
    int pitch = width * sizeof(uint16_t); // Assuming J16SAMPLE is a 16-bit integer
    int pixelFormat = TJPF_RGB;

    // Output buffer
    unsigned char *jpegBuf = NULL;
    size_t jpegSize = 0;

    // Call the function-under-test
    int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

    // Clean up
    if (jpegBuf != NULL) {
        tjFree(jpegBuf);
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

    LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
