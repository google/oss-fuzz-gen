#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    if (size < 24) {
        return 0; // Ensure there is enough data for all parameters
    }

    // Initialize profiles
    cmsHPROFILE inputProfile = cmsOpenProfileFromMem(data, size / 3);
    cmsHPROFILE outputProfile = cmsOpenProfileFromMem(data + size / 3, size / 3);
    cmsHPROFILE proofingProfile = cmsOpenProfileFromMem(data + 2 * (size / 3), size / 3);

    if (inputProfile == NULL || outputProfile == NULL || proofingProfile == NULL) {
        if (inputProfile != NULL) cmsCloseProfile(inputProfile);
        if (outputProfile != NULL) cmsCloseProfile(outputProfile);
        if (proofingProfile != NULL) cmsCloseProfile(proofingProfile);
        return 0;
    }

    // Extract cmsUInt32Number values from the data
    cmsUInt32Number inputFormat = *(cmsUInt32Number *)(data + size - 16);
    cmsUInt32Number outputFormat = *(cmsUInt32Number *)(data + size - 12);
    cmsUInt32Number proofingIntent = *(cmsUInt32Number *)(data + size - 8);
    cmsUInt32Number flags = *(cmsUInt32Number *)(data + size - 4);

    // Call the function under test
    cmsHTRANSFORM transform = cmsCreateProofingTransform(
        inputProfile, inputFormat, 
        outputProfile, outputFormat, 
        proofingProfile, proofingIntent, 
        flags, 0);

    // Cleanup
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    cmsCloseProfile(proofingProfile);

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

    LLVMFuzzerTestOneInput_183(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
