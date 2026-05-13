#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsToneCurve *toneCurve = NULL;
    cmsUInt32Number nEntries = 0;
    cmsFloat32Number *values = NULL;

    if (size < sizeof(cmsUInt32Number)) {
        goto cleanup;
    }

    // Ensure we have enough data to extract nEntries
    nEntries = *(cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Ensure there is enough data for the float array
    if (size < nEntries * sizeof(cmsFloat32Number)) {
        goto cleanup;
    }

    values = (cmsFloat32Number *)malloc(nEntries * sizeof(cmsFloat32Number));
    if (values == NULL) {
        goto cleanup;
    }

    // Copy the data into the float array
    for (cmsUInt32Number i = 0; i < nEntries; i++) {
        values[i] = ((cmsFloat32Number *)data)[i];
    }

    // Call the function-under-test
    toneCurve = cmsBuildTabulatedToneCurveFloat(context, nEntries, values);

cleanup:
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
    }
    if (values != NULL) {
        free(values);
    }
    if (context != NULL) {
        cmsDeleteContext(context);
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

    LLVMFuzzerTestOneInput_27(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
