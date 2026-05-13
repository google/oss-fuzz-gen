#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a cmsToneCurve
    // Instead of using sizeof(cmsToneCurve), we should use a reasonable minimum size
    // for a tone curve, let's assume at least 2 entries are needed.
    if (size < 2 * sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Create a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a tone curve using the input data
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(context, size / sizeof(cmsUInt16Number), (cmsUInt16Number *)data);

    // Ensure the toneCurve is not NULL
    if (toneCurve == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    const cmsUInt16Number *estimatedTable = cmsGetToneCurveEstimatedTable(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
