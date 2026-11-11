#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;

    // Ensure that the data size is sufficient to create a tone curve
    if (size >= sizeof(cmsUInt16Number)) {
        // Allocate memory for tone curve data
        cmsUInt16Number *curveData = (cmsUInt16Number *)malloc(size);
        if (curveData == NULL) {
            return 0; // Allocation failed, exit
        }

        // Copy the input data into curveData
        for (size_t i = 0; i < size / sizeof(cmsUInt16Number); i++) {
            curveData[i] = ((cmsUInt16Number *)data)[i];
        }

        // Create a tone curve using the input data
        toneCurve = cmsBuildTabulatedToneCurve16(NULL, size / sizeof(cmsUInt16Number), curveData);

        // Free the allocated memory for curveData
        free(curveData);
    }

    if (toneCurve != NULL) {
        // Call the function-under-test
        cmsUInt32Number estimatedEntries = cmsGetToneCurveEstimatedTableEntries(toneCurve);

        // Clean up the tone curve
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

    LLVMFuzzerTestOneInput_224(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
