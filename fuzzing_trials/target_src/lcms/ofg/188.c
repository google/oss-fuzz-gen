#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    cmsToneCurve *originalCurve = NULL;
    cmsToneCurve *duplicatedCurve = NULL;

    // Ensure the data size is sufficient to create a tone curve
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Create a tone curve with a single segment using the input data
    uint16_t gamma = data[0] | (data[1] << 8);  // Use the first two bytes as gamma value
    originalCurve = cmsBuildGamma(NULL, gamma);

    if (originalCurve != NULL) {
        // Call the function-under-test
        duplicatedCurve = cmsDupToneCurve(originalCurve);

        // Free the duplicated curve if it was successfully created
        if (duplicatedCurve != NULL) {
            cmsFreeToneCurve(duplicatedCurve);
        }

        // Free the original curve
        cmsFreeToneCurve(originalCurve);
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

    LLVMFuzzerTestOneInput_188(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
