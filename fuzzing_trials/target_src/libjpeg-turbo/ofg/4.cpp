#include <stddef.h>
#include <stdint.h>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Return early if size is zero to avoid unnecessary processing
    }

    tjhandle handle = tj3Init(TJINIT_COMPRESS); // Initialize a TurboJPEG handle for compression
    if (!handle) {
        return 0; // If initialization fails, exit
    }

    unsigned char *iccProfile = new unsigned char[size];
    if (!iccProfile) {
        tj3Destroy(handle);
        return 0; // If memory allocation fails, exit
    }

    // Copy the input data to the ICC profile buffer
    for (size_t i = 0; i < size; ++i) {
        iccProfile[i] = data[i];
    }

    // Call the function-under-test
    int result = tj3SetICCProfile(handle, iccProfile, size);

    // Clean up
    delete[] iccProfile;
    tj3Destroy(handle);

    return result;
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
