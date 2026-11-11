#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_288(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for a gamma value
    if (size < sizeof(double)) {
        return 0;
    }

    // Interpret the first bytes of data as a gamma value
    double gamma;
    memcpy(&gamma, data, sizeof(double));

    // Create a cmsToneCurve using the gamma value
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, gamma);
    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsInt32Number parametricType = cmsGetToneCurveParametricType(toneCurve);

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

    LLVMFuzzerTestOneInput_288(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
