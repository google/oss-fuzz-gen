#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract three 32-bit integers and a minimum buffer size
    if (size < 3 * sizeof(cmsUInt32Number) + 1) {
        return 0;
    }

    // Extract cmsUInt32Number values from the input data
    cmsUInt32Number format1 = *(const cmsUInt32Number*)(data);
    cmsUInt32Number format2 = *(const cmsUInt32Number*)(data + sizeof(cmsUInt32Number));
    cmsUInt32Number dummyTransformValue = *(const cmsUInt32Number*)(data + 2 * sizeof(cmsUInt32Number));

    // Create a dummy transform for testing
    // For fuzzing, we should create a valid transform using lcms2 functions
    cmsHPROFILE hInProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE hOutProfile = cmsCreate_sRGBProfile();

    if (hInProfile == NULL || hOutProfile == NULL) {
        if (hInProfile) cmsCloseProfile(hInProfile);
        if (hOutProfile) cmsCloseProfile(hOutProfile);
        return 0;
    }

    cmsHTRANSFORM transform = cmsCreateTransform(hInProfile, format1, hOutProfile, format2, INTENT_PERCEPTUAL, 0);

    // Release the profiles as they are no longer needed
    cmsCloseProfile(hInProfile);
    cmsCloseProfile(hOutProfile);

    if (transform == NULL) {
        return 0;
    }

    // Call the function under test
    cmsBool result = cmsChangeBuffersFormat(transform, format1, format2);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

    // Free the transform
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
