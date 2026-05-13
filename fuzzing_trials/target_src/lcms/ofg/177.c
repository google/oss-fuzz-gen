#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat32Number)) {
        return 0; // Not enough data to create a tone curve
    }

    cmsToneCurve *toneCurve = NULL;
    cmsFloat32Number *values = (cmsFloat32Number *)malloc(size);

    if (values == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the input data to the values array
    for (size_t i = 0; i < size / sizeof(cmsFloat32Number); i++) {
        values[i] = ((cmsFloat32Number *)data)[i];
    }

    // Create a tone curve with the data
    toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, size / sizeof(cmsFloat32Number), values);

    if (toneCurve != NULL) {
        // Call the function-under-test
        cmsBool isMultisegment = cmsIsToneCurveMultisegment(toneCurve);

        // Clean up
        cmsFreeToneCurve(toneCurve);
    }

    free(values);

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

    LLVMFuzzerTestOneInput_177(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
