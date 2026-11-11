#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_461(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to initialize the structures
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(cmsToneCurve *)) {
        return 0;
    }

    // Initialize cmsCIExyY
    cmsCIExyY whitePoint;
    whitePoint.x = (double)data[0] / 255.0;
    whitePoint.y = (double)data[1] / 255.0;
    whitePoint.Y = (double)data[2] / 255.0;

    // Initialize cmsCIExyYTRIPLE
    cmsCIExyYTRIPLE primaries;
    primaries.Red.x = (double)data[3] / 255.0;
    primaries.Red.y = (double)data[4] / 255.0;
    primaries.Red.Y = (double)data[5] / 255.0;
    primaries.Green.x = (double)data[6] / 255.0;
    primaries.Green.y = (double)data[7] / 255.0;
    primaries.Green.Y = (double)data[8] / 255.0;
    primaries.Blue.x = (double)data[9] / 255.0;
    primaries.Blue.y = (double)data[10] / 255.0;
    primaries.Blue.Y = (double)data[11] / 255.0;

    // Initialize cmsToneCurve array
    cmsToneCurve *toneCurves[3];
    for (int i = 0; i < 3; i++) {
        toneCurves[i] = cmsBuildGamma(NULL, 2.2); // Use a standard gamma value
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateRGBProfile(&whitePoint, &primaries, (const cmsToneCurve **)toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    for (int i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
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

    LLVMFuzzerTestOneInput_461(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
