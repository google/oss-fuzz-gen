#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_251(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;
    cmsBool result;

    // Ensure the data size is sufficient for creating a profile
    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Initialize intent and flags from the input data
    intent = *(cmsUInt32Number *)data;
    flags = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    result = cmsIsCLUT(hProfile, intent, flags);

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

    LLVMFuzzerTestOneInput_251(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
