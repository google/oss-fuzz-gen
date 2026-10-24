#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (handle == nullptr) {
        return 0;
    }

    // Check if the input size is sufficient for a minimal JPEG header
    if (size < 2 || data[0] != 0xFF || data[1] != 0xD8) {
        tj3Destroy(handle);
        return 0;
    }

    // Initialize the output variables for tj3GetICCProfile
    unsigned char *iccProfile = nullptr;
    size_t iccProfileSize = 0;

    // Call the function-under-test with input data
    int result = tj3GetICCProfile(handle, &iccProfile, &iccProfileSize);

    // Clean up
    if (iccProfile != nullptr) {
        tj3Free(iccProfile);
    }
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
