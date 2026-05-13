#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_380(const uint8_t *data, size_t size) {
    // Ensure there is enough data to fill two cmsCIELab structures
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize two cmsCIELab structures
    cmsCIELab Lab1, Lab2;

    // Fill the cmsCIELab structures with data from the input
    // Each cmsCIELab has L, a, b components which are cmsFloat64Number
    Lab1.L = *((cmsFloat64Number*)data);
    Lab1.a = *((cmsFloat64Number*)(data + sizeof(cmsFloat64Number)));
    Lab1.b = *((cmsFloat64Number*)(data + 2 * sizeof(cmsFloat64Number)));

    Lab2.L = *((cmsFloat64Number*)(data + 3 * sizeof(cmsFloat64Number)));
    Lab2.a = *((cmsFloat64Number*)(data + 4 * sizeof(cmsFloat64Number)));
    Lab2.b = *((cmsFloat64Number*)(data + 5 * sizeof(cmsFloat64Number)));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsDeltaE(&Lab1, &Lab2);

    // Use the result to prevent the compiler from optimizing the call away
    volatile cmsFloat64Number result = deltaE;
    (void)result;

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

    LLVMFuzzerTestOneInput_380(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
