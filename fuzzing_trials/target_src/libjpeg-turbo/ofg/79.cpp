#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract four integers
    if (size < sizeof(int) * 4) {
        return 0;
    }

    // Extract four integers from the input data
    int width = *(reinterpret_cast<const int*>(data));
    int height = *(reinterpret_cast<const int*>(data + sizeof(int)));
    int subsamp = *(reinterpret_cast<const int*>(data + 2 * sizeof(int)));
    int align = *(reinterpret_cast<const int*>(data + 3 * sizeof(int)));

    // Call the function-under-test
    unsigned long bufferSize = tjBufSizeYUV2(width, height, subsamp, align);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (bufferSize == 0) {
        // Handle the case where the buffer size is zero, if necessary
    }

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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
