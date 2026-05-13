#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitCompress(); // Initialize TurboJPEG compressor handle
    if (handle == nullptr) {
        return 0; // Return if handle initialization fails
    }

    // Initialize a tjregion structure with non-NULL values
    tjregion region;
    region.x = size > 0 ? data[0] % 256 : 0; // Use data to set x
    region.y = size > 1 ? data[1] % 256 : 0; // Use data to set y
    region.w = size > 2 ? data[2] % 256 : 1; // Use data to set width, ensure it's non-zero
    region.h = size > 3 ? data[3] % 256 : 1; // Use data to set height, ensure it's non-zero

    // Call the function-under-test
    tj3SetCroppingRegion(handle, region); // Pass region directly, not as a pointer

    // Clean up
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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
