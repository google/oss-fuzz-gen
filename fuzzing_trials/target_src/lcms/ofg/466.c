#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_466(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurves[3];

    // Use the fuzzing input to influence the gamma value
    if (size < 3) {
        return 0; // Not enough data to influence all three curves
    }

    for (int i = 0; i < 3; i++) {
        // Convert a byte from the input data to a gamma value in a reasonable range
        double gamma = 1.0 + (data[i] / 255.0) * 4.0; // Range from 1.0 to 5.0
        toneCurves[i] = cmsBuildGamma(NULL, gamma);
        if (toneCurves[i] == NULL) {
            return 0; // If initialization fails, exit early
        }
    }

    // Call the function-under-test
    cmsFreeToneCurveTriple(toneCurves);

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

    LLVMFuzzerTestOneInput_466(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
