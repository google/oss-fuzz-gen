#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nSegments = 1; // Assuming at least one segment
    cmsCurveSegment segment;
    cmsCurveSegment* segments = &segment;

    // Ensure size is sufficient to populate cmsCurveSegment
    if (size < sizeof(cmsCurveSegment)) {
        return 0;
    }

    // Populate cmsCurveSegment with data
    segment.nGridPoints = 2; // Minimum number of grid points
    segment.x0 = 0.0;
    segment.x1 = 1.0;
    segment.Type = cmsSigFormulaCurveSeg;

    // Assuming the data contains enough bytes to fill the parameters
    // Copy data into segment.Params
    memcpy(segment.Params, data, sizeof(segment.Params));

    // Call the function-under-test
    cmsToneCurve* toneCurve = cmsBuildSegmentedToneCurve(context, nSegments, segments);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_66(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
