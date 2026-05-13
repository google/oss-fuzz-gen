#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_344(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(cmsInt32Number) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Extract cmsInt32Number from data
    cmsInt32Number parametricType = *(cmsInt32Number *)data;
    data += sizeof(cmsInt32Number);
    size -= sizeof(cmsInt32Number);

    // Allocate space for cmsFloat64Number array
    size_t numParams = size / sizeof(cmsFloat64Number);
    cmsFloat64Number *params = (cmsFloat64Number *)malloc(numParams * sizeof(cmsFloat64Number));

    // Copy data into the cmsFloat64Number array
    for (size_t i = 0; i < numParams; i++) {
        params[i] = ((cmsFloat64Number *)data)[i];
    }

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildParametricToneCurve(context, parametricType, params);

    // Clean up
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    free(params);
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

    LLVMFuzzerTestOneInput_344(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
