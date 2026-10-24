#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_353(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt64Number attributes;

    // Ensure there is enough data to extract cmsUInt64Number
    if (size < sizeof(cmsUInt64Number)) {
        return 0;
    }

    // Initialize attributes from input data
    attributes = *((cmsUInt64Number*)data);

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsSetHeaderAttributes(hProfile, attributes);

    // Close the profile after use
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

    LLVMFuzzerTestOneInput_353(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
