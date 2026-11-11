#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (size < sizeof(cmsCurveSegment)) {
        return 0;
    }

    // Create a tone curve with a single segment
    cmsCurveSegment segment;
    segment.nGridPoints = 2;
    segment.SampledPoints = (cmsFloat32Number*)data;
    segment.x0 = 0.0;
    segment.x1 = 1.0;

    toneCurve = cmsBuildSegmentedToneCurve(context, 1, &segment);

    if (toneCurve != NULL) {
        cmsBool result = cmsIsToneCurveLinear(toneCurve);
        (void)result; // Use the result to avoid unused variable warning
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

    LLVMFuzzerTestOneInput_221(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
