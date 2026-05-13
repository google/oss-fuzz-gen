#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to hold at least one float value
    if (size < sizeof(float)) {
        return 0;
    }

    // Create a tone curve with a single gamma value derived from the input data
    float gamma = *((float*)data);
    cmsToneCurve *originalCurve = cmsBuildGamma(NULL, gamma);

    // Check if the original curve was created successfully
    if (originalCurve == NULL) {
        return 0;
    }

    // Duplicate the tone curve
    cmsToneCurve *duplicateCurve = cmsDupToneCurve(originalCurve);

    // Free the original and duplicated tone curves
    cmsFreeToneCurve(originalCurve);
    if (duplicateCurve != NULL) {
        cmsFreeToneCurve(duplicateCurve);
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

    LLVMFuzzerTestOneInput_189(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
