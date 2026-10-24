#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract parameters
    if (size < sizeof(cmsUInt32Number) * 5) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE profiles[2];
    cmsUInt32Number nProfiles, inputFormat, outputFormat, intent, flags;

    // Create dummy profiles for testing
    profiles[0] = cmsCreate_sRGBProfile();
    profiles[1] = cmsCreate_sRGBProfile();

    // Extract cmsUInt32Number values from data
    nProfiles = *(cmsUInt32Number *)(data);
    inputFormat = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number));
    outputFormat = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number) * 2);
    intent = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number) * 3);
    flags = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number) * 4);

    // Ensure nProfiles is within the bounds of the profiles array
    nProfiles = nProfiles % 2 + 1; // Ensure at least one profile

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(profiles, nProfiles, inputFormat, outputFormat, intent, flags);

    // Clean up if necessary
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }

    // Clean up profiles
    cmsCloseProfile(profiles[0]);
    cmsCloseProfile(profiles[1]);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
