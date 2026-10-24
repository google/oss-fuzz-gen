#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

// Define a simple tone curve for testing
cmsToneCurve* createTestToneCurve() {
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value
    return toneCurve;
}

int LLVMFuzzerTestOneInput_372(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0; // Not enough data to form a cmsFloat64Number
    }

    // Create a test tone curve
    cmsToneCurve* toneCurve = createTestToneCurve();
    if (toneCurve == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number inputNumber;
    memcpy(&inputNumber, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsFloat64Number result = cmsEstimateGamma(toneCurve, inputNumber);

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

    LLVMFuzzerTestOneInput_372(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
