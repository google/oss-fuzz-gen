#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Ensure there is enough data for cmsHPROFILE and cmsProfileClassSignature
    if (size < sizeof(cmsProfileClassSignature)) {
        return 0;
    }

    // Create a memory-based profile for fuzzing
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Extract cmsProfileClassSignature from the input data
    cmsProfileClassSignature deviceClass = *(cmsProfileClassSignature *)data;

    // Call the function-under-test
    cmsSetDeviceClass(hProfile, deviceClass);

    // Close the profile
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

    LLVMFuzzerTestOneInput_123(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
