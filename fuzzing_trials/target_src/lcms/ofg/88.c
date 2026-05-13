#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Define a reasonable minimum number of elements for the tone curve
    const size_t min_elements = 2; // Assuming at least 2 elements are needed

    // Ensure that size is sufficient to create a tone curve with the minimum number of elements
    if (size < min_elements * sizeof(uint16_t)) {
        return 0;
    }

    cmsToneCurve *toneCurve = cmsBuildTabulatedToneCurve16(NULL, size / sizeof(uint16_t), (const uint16_t *)data);
    if (toneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIsToneCurveMonotonic(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);

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

    LLVMFuzzerTestOneInput_88(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
