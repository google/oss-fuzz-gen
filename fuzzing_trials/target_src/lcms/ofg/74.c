#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    // Check if size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract cmsUInt32Number from the input data
    cmsUInt32Number nPoints;
    memcpy(&nPoints, data, sizeof(cmsUInt32Number));
    
    // Ensure nPoints is non-zero to avoid invalid operations
    if (nPoints == 0) {
        nPoints = 1;
    }

    // Create a dummy cmsToneCurve
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // A simple gamma curve

    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function under test
    cmsToneCurve *reversedCurve = cmsReverseToneCurveEx(nPoints, toneCurve);

    // Clean up
    if (reversedCurve != NULL) {
        cmsFreeToneCurve(reversedCurve);
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

    LLVMFuzzerTestOneInput_74(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
