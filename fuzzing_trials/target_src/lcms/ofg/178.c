#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = NULL; // Assuming context can be NULL for testing purposes
    cmsCIExyY whitePoint;
    cmsToneCurve *toneCurve = NULL;

    // Check if the input size is sufficient for initializing cmsCIExyY and gamma
    if (size < 4) {
        return 0;
    }

    // Initialize cmsCIExyY from input data
    whitePoint.x = ((double)data[0] / 255.0);
    whitePoint.y = ((double)data[1] / 255.0);
    whitePoint.Y = ((double)data[2] / 255.0);

    // Create a tone curve with a gamma value from the input data
    double gamma = ((double)data[3] / 255.0) + 0.1; // Ensure gamma is non-zero
    toneCurve = cmsBuildGamma(context, gamma);

    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateGrayProfileTHR(context, &whitePoint, toneCurve);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsFreeToneCurve(toneCurve);

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

    LLVMFuzzerTestOneInput_178(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
