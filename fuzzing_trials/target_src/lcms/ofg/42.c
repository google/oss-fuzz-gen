#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize a cmsToneCurve object
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value

    // Extract a cmsFloat64Number from the input data
    cmsFloat64Number smoothnessValue;
    memcpy(&smoothnessValue, data, sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsBool result = cmsSmoothToneCurve(toneCurve, smoothnessValue);

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

    LLVMFuzzerTestOneInput_42(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
