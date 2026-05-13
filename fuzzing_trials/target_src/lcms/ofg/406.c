#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_406(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize cmsCIExyY
    if (size < 3 * sizeof(double)) {
        return 0;
    }

    // Initialize cmsCIExyY structure
    cmsCIExyY whitePoint;
    whitePoint.x = *(double*)data;
    whitePoint.y = *(double*)(data + sizeof(double));
    whitePoint.Y = *(double*)(data + 2 * sizeof(double));

    // Initialize cmsToneCurve structure
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value

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

    LLVMFuzzerTestOneInput_406(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
