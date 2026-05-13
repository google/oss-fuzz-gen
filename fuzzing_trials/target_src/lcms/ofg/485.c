#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_485(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for cmsTagSignature and cmsUInt32Number
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile;
    cmsTagSignature tagSig;
    const void *tagData;
    cmsUInt32Number tagSize;

    // Create a dummy profile
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract cmsTagSignature from the input data
    tagSig = *(cmsTagSignature *)data;

    // Extract cmsUInt32Number from the input data
    tagSize = *(cmsUInt32Number *)(data + sizeof(cmsTagSignature));

    // Point to the remaining data as the tag data
    tagData = (const void *)(data + sizeof(cmsTagSignature) + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsBool result = cmsWriteRawTag(hProfile, tagSig, tagData, tagSize);

    // Cleanup
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

    LLVMFuzzerTestOneInput_485(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
