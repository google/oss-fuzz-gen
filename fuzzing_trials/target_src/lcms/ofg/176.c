#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;

    // Ensure size is large enough to create a tone curve
    if (size < sizeof(cmsCurveSegment)) {
        return 0;
    }

    // Create a tone curve with one segment using the data provided
    cmsCurveSegment segment;
    segment.nGridPoints = (cmsUInt32Number)(data[0] % 256) + 2; // Ensure at least 2 grid points
    segment.SampledPoints = (cmsFloat32Number *)malloc(segment.nGridPoints * sizeof(cmsFloat32Number));

    if (segment.SampledPoints == NULL) {
        return 0;
    }

    // Fill the SampledPoints with data
    for (cmsUInt32Number i = 0; i < segment.nGridPoints; ++i) {
        segment.SampledPoints[i] = (cmsFloat32Number)data[i % size] / 255.0f; // Normalize to [0, 1]
    }

    // Create a tone curve with the segment
    toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, segment.nGridPoints, segment.SampledPoints);

    // Check if the tone curve is multisegment
    if (toneCurve != NULL) {
        cmsBool result = cmsIsToneCurveMultisegment(toneCurve);
        (void)result; // Use the result to avoid unused variable warning
    }

    // Free resources
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    free(segment.SampledPoints);

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

    LLVMFuzzerTestOneInput_176(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
