#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = (cmsContext)0x1;  // Dummy non-NULL context
    cmsUInt32Number nEntries = 2;          // Minimum valid number of entries
    cmsFloat32Number values[2] = {0.0f, 1.0f}; // Default values for the tone curve

    // Ensure we have enough data to work with
    if (size >= sizeof(cmsFloat32Number) * nEntries) {
        // Use the provided data to initialize the tone curve values
        for (cmsUInt32Number i = 0; i < nEntries; i++) {
            values[i] = ((cmsFloat32Number*)data)[i];
        }
    }

    // Call the function under test
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurveFloat(context, nEntries, values);

    // Clean up
    if (toneCurve != NULL) {
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

    LLVMFuzzerTestOneInput_26(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
