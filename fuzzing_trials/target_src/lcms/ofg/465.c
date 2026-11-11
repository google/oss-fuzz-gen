#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_465(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create cmsToneCurve objects
    // We don't need sizeof(cmsToneCurve) since we're not directly using its size
    if (size < 3) {
        return 0;
    }

    // Allocate memory for three cmsToneCurve pointers
    cmsToneCurve *toneCurves[3];

    // Initialize each cmsToneCurve object
    for (int i = 0; i < 3; i++) {
        // Create a cmsToneCurve object using the data provided
        toneCurves[i] = cmsBuildGamma(NULL, 2.2); // Use a gamma value for initialization
        if (toneCurves[i] == NULL) {
            // If initialization fails, free any allocated tone curves and return
            for (int j = 0; j < i; j++) {
                cmsFreeToneCurve(toneCurves[j]);
            }
            return 0;
        }
    }

    // Free each cmsToneCurve individually
    for (int i = 0; i < 3; i++) {
        cmsFreeToneCurve(toneCurves[i]);
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

    LLVMFuzzerTestOneInput_465(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
