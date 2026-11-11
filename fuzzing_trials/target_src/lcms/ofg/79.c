#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Ensure there is enough data to construct a cmsToneCurve object
    // Since cmsToneCurve is an incomplete type, we cannot use sizeof directly.
    // Instead, ensure there is enough data to open a profile.
    if (size < 4) { // Arbitrary minimum size to attempt to open a profile
        return 0;
    }

    // Create a memory pool for the tone curve
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Create a tone curve from the profile
    cmsToneCurve *toneCurve = cmsReadTag(hProfile, cmsSigGrayTRCTag);
    if (toneCurve == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Use a fixed cmsUInt16Number value for fuzzing
    cmsUInt16Number inputValue = 12345;  // Arbitrary non-zero value

    // Call the function-under-test
    cmsUInt16Number result = cmsEvalToneCurve16(toneCurve, inputValue);

    // Clean up
    cmsFreeToneCurve(toneCurve);
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

    LLVMFuzzerTestOneInput_79(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
