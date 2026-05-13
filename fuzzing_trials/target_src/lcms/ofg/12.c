#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsUInt32Number intent;
    cmsUInt32Number flags;

    if (size < sizeof(cmsUInt32Number) * 2) {
        return 0; // Not enough data to extract intent and flags
    }

    // Initialize the profile using cmsOpenProfileFromMem
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0; // Failed to create a profile from the data
    }

    // Extract intent and flags from the data
    intent = *(cmsUInt32Number *)(data);
    flags = *(cmsUInt32Number *)(data + sizeof(cmsUInt32Number));

    // Call the function-under-test
    cmsBool result = cmsIsIntentSupported(hProfile, intent, flags);

    // Clean up
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

    LLVMFuzzerTestOneInput_12(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
