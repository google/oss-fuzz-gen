#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a tone curve
    if (size < 4) {
        return 0;
    }

    // Extract the number of segments from the input data
    uint16_t nSegments = (data[0] << 8) | data[1];
    if (nSegments == 0) {
        return 0;
    }

    // Ensure there is enough data for the segments
    if (size < 4 + nSegments * sizeof(cmsCurveSegment)) {
        return 0;
    }

    // Create a tone curve using the extracted segments
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(NULL, nSegments, (const uint16_t *)(data + 2));
    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIsToneCurveMonotonic(toneCurve);

    // Clean up
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

    LLVMFuzzerTestOneInput_87(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
