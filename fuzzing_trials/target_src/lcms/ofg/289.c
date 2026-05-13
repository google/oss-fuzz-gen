#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_289(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;
    cmsUInt32Number inputFormat, outputFormat;

    // Ensure we have enough data to extract two cmsUInt32Number values
    if (size < 2 * sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the inputFormat and outputFormat from the data
    inputFormat = *((cmsUInt32Number*)data);
    outputFormat = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number)));

    // Create a dummy transform for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    transform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    cmsCloseProfile(hProfile);

    // Call the function-under-test
    cmsBool result = cmsChangeBuffersFormat(transform, inputFormat, outputFormat);

    // Clean up
    cmsDeleteTransform(transform);

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

    LLVMFuzzerTestOneInput_289(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
