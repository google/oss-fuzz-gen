#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_327(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(cmsUInt32Number) + sizeof(cmsUInt16Number)) {
        return 0;
    }
    
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0;
    }

    // Extract cmsUInt32Number from the input data
    cmsUInt32Number nEntries = *(const cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Ensure we have enough data for the tone curve entries
    if (size < nEntries * sizeof(cmsUInt16Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract cmsUInt16Number array from the input data
    const cmsUInt16Number *toneCurveEntries = (const cmsUInt16Number *)data;

    // Call the function-under-test
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(context, nEntries, toneCurveEntries);

    // Clean up
    if (toneCurve) {
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

    LLVMFuzzerTestOneInput_327(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
