#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Declare and initialize the variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsToneCurve *curve1 = NULL;
    cmsToneCurve *curve2 = NULL;
    cmsUInt32Number location = 0;

    // Ensure size is sufficient to create tone curves
    if (size < 2) {
        return 0;
    }

    // Create tone curves with some sample points
    cmsUInt16Number samplePoints1[] = { 0, 65535 };
    cmsUInt16Number samplePoints2[] = { 65535, 0 };

    curve1 = cmsBuildTabulatedToneCurve16(context, 2, samplePoints1);
    curve2 = cmsBuildTabulatedToneCurve16(context, 2, samplePoints2);

    // Use the first byte of data as the location
    location = (cmsUInt32Number)data[0];

    // Call the function under test
    cmsToneCurve *resultCurve = cmsJoinToneCurve(context, curve1, curve2, location);

    // Clean up
    if (resultCurve != NULL) {
        cmsFreeToneCurve(resultCurve);
    }
    if (curve1 != NULL) {
        cmsFreeToneCurve(curve1);
    }
    if (curve2 != NULL) {
        cmsFreeToneCurve(curve2);
    }
    cmsDeleteContext(context);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
