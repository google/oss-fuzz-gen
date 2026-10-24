#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_260(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsToneCurve *curve1 = NULL;
    cmsToneCurve *curve2 = NULL;
    cmsToneCurve *result = NULL;
    cmsUInt32Number location = 0;

    if (size < 2) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create tone curves from the input data
    curve1 = cmsBuildGamma(context, 2.2);  // Example gamma value
    curve2 = cmsBuildGamma(context, 1.8);  // Example gamma value

    // Use the first byte of data as the location parameter
    location = data[0];

    // Call the function-under-test
    result = cmsJoinToneCurve(context, curve1, curve2, location);

    // Clean up
    if (result != NULL) {
        cmsFreeToneCurve(result);
    }
    if (curve1 != NULL) {
        cmsFreeToneCurve(curve1);
    }
    if (curve2 != NULL) {
        cmsFreeToneCurve(curve2);
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

    LLVMFuzzerTestOneInput_260(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
