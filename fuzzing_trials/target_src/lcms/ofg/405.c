#include <stdint.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_405(const uint8_t *data, size_t size) {
    // Ensure we have enough data to read for cmsCIExyY
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Initialize cmsCIExyY from input data
    cmsCIExyY whitePoint;
    memcpy(&whitePoint, data, sizeof(cmsCIExyY));

    // Move the data pointer forward
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);

    // Initialize cmsToneCurve with a default gamma value
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Default gamma value

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateGrayProfile(&whitePoint, toneCurve);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }

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

    LLVMFuzzerTestOneInput_405(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
