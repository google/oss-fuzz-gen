#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a tone curve
    if (size < sizeof(cmsFloat32Number)) {
        return 0;
    }

    // Create a tone curve with at least one segment
    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, size / sizeof(cmsFloat32Number), (cmsFloat32Number *)data);

    if (toneCurve != NULL) {
        // Call the function under test
        cmsBool result = cmsIsToneCurveDescending(toneCurve);

        // Free the tone curve
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

    LLVMFuzzerTestOneInput_69(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
