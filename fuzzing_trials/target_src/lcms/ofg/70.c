#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a cmsToneCurve
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Allocate memory for tone curve points
    cmsFloat32Number *curvePoints = (cmsFloat32Number *)malloc(size);
    if (curvePoints == NULL) {
        return 0;
    }

    // Copy data into curve points
    for (size_t i = 0; i < size / sizeof(cmsFloat32Number); i++) {
        curvePoints[i] = ((cmsFloat32Number *)data)[i];
    }

    // Create a tone curve with the provided points
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, size / sizeof(cmsFloat32Number), curvePoints);
    if (toneCurve == NULL) {
        free(curvePoints);
        return 0;
    }

    // Call the function-under-test
    cmsBool isDescending = cmsIsToneCurveDescending(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);
    free(curvePoints);

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

    LLVMFuzzerTestOneInput_70(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
