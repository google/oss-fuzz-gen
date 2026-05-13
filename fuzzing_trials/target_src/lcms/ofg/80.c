#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt16Number)) {
        return 0; // Not enough data to form a cmsUInt16Number
    }

    // Initialize a cmsToneCurve object
    cmsToneCurve *toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value

    if (toneCurve == NULL) {
        return 0; // Failed to create tone curve
    }

    // Extract a cmsUInt16Number from the input data
    cmsUInt16Number inputValue = *(const cmsUInt16Number *)data;

    // Call the function-under-test
    cmsUInt16Number outputValue = cmsEvalToneCurve16(toneCurve, inputValue);

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

    LLVMFuzzerTestOneInput_80(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
