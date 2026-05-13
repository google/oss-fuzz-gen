#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract five integers
    if (size < 5 * sizeof(int)) {
        return 0;
    }

    // Extract five integers from the input data
    int width = static_cast<int>(data[0]);
    int height = static_cast<int>(data[1]);
    int subsamp = static_cast<int>(data[2]);
    int align = static_cast<int>(data[3]);
    int plane = static_cast<int>(data[4]);

    // Call the function-under-test
    unsigned long result = tjPlaneSizeYUV(plane, width, height, subsamp, align);

    // Use the result to avoid any compiler optimizations that might skip the function call
    volatile unsigned long avoid_optimization = result;
    (void)avoid_optimization;

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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
