#include <sys/stat.h>
#include <stdint.h>
#include "lcms2.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < 32) {
        return 0;
    }

    // Extract parameters from the input data
    cmsUInt32Number InputFormat = (cmsUInt32Number)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));
    cmsUInt32Number OutputFormat = (cmsUInt32Number)(data[12] | (data[13] << 8) | (data[14] << 16) | (data[15] << 24));
    cmsUInt32Number ProofingIntent = (cmsUInt32Number)(data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24));
    cmsUInt32Number Intent = (cmsUInt32Number)(data[24] | (data[25] << 8) | (data[26] << 16) | (data[27] << 24));
    cmsUInt32Number Flags = (cmsUInt32Number)(data[28] | (data[29] << 8) | (data[30] << 16) | (data[31] << 24));

    // Create dummy profiles for testing
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cmsCreate_sRGBProfile with cmsCreateXYZProfile
    cmsHPROFILE hInputProfile = cmsCreateXYZProfile();
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    cmsHPROFILE hOutputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE hProofingProfile = cmsCreate_sRGBProfile();

    if (hInputProfile == NULL || hOutputProfile == NULL || hProofingProfile == NULL) {
        if (hInputProfile) {
                cmsCloseProfile(hInputProfile);
        }
        if (hOutputProfile) {
                cmsCloseProfile(hOutputProfile);
        }
        if (hProofingProfile) {
                cmsCloseProfile(hProofingProfile);
        }
        return 0;
    }

    // Create a proofing transform
    cmsHTRANSFORM transform = cmsCreateProofingTransform(
        hInputProfile,
        InputFormat,
        hOutputProfile,
        OutputFormat,
        hProofingProfile,
        ProofingIntent,
        Intent,
        Flags
    );

    // Clean up if the transform was successfully created
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }

    // Close profiles
    cmsCloseProfile(hInputProfile);
    cmsCloseProfile(hOutputProfile);
    cmsCloseProfile(hProofingProfile);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
