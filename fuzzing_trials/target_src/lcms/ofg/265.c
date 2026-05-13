#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_265(const uint8_t *data, size_t size) {
    // Ensure there is enough data for two cmsCIELab structures and two cmsFloat64Number values
    if (size < 2 * sizeof(cmsCIELab) + 2 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize cmsCIELab structures
    cmsCIELab Lab1, Lab2;
    cmsFloat64Number L1, a1, b1, L2, a2, b2;

    // Copy data into the cmsCIELab structures
    L1 = *((cmsFloat64Number *)(data));
    a1 = *((cmsFloat64Number *)(data + sizeof(cmsFloat64Number)));
    b1 = *((cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number)));
    Lab1.L = L1;
    Lab1.a = a1;
    Lab1.b = b1;

    L2 = *((cmsFloat64Number *)(data + 3 * sizeof(cmsFloat64Number)));
    a2 = *((cmsFloat64Number *)(data + 4 * sizeof(cmsFloat64Number)));
    b2 = *((cmsFloat64Number *)(data + 5 * sizeof(cmsFloat64Number)));
    Lab2.L = L2;
    Lab2.a = a2;
    Lab2.b = b2;

    // Initialize cmsFloat64Number values for the fuzzing
    cmsFloat64Number weightL = *((cmsFloat64Number *)(data + 6 * sizeof(cmsFloat64Number)));
    cmsFloat64Number weightC = *((cmsFloat64Number *)(data + 7 * sizeof(cmsFloat64Number)));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCMCdeltaE(&Lab1, &Lab2, weightL, weightC);

    // Use the result in some way to avoid optimization issues
    (void)deltaE;

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

    LLVMFuzzerTestOneInput_265(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
