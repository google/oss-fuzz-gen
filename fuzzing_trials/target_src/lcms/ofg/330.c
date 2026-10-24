#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_330(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number dwFlags;
    cmsBool lIsInput;

    // Ensure the input size is sufficient for the parameters
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsBool)) {
        return 0;
    }

    // Initialize the parameters from the input data
    dwFlags = *(const cmsUInt32Number *)data;
    lIsInput = *(const cmsBool *)(data + sizeof(cmsUInt32Number));

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsFormatterForPCSOfProfile(hProfile, dwFlags, lIsInput);

    // Clean up the profile
    cmsCloseProfile(hProfile);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_330(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
