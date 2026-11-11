#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsCIELab Lab1;
    cmsCIELab Lab2;

    // Initialize cmsCIELab structures with data
    Lab1.L = *((cmsFloat64Number *)(data));
    Lab1.a = *((cmsFloat64Number *)(data + sizeof(cmsFloat64Number)));
    Lab1.b = *((cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number)));

    Lab2.L = *((cmsFloat64Number *)(data + 3 * sizeof(cmsFloat64Number)));
    Lab2.a = *((cmsFloat64Number *)(data + 4 * sizeof(cmsFloat64Number)));
    Lab2.b = *((cmsFloat64Number *)(data + 5 * sizeof(cmsFloat64Number)));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCIE94DeltaE(&Lab1, &Lab2);

    // Use deltaE to avoid unused variable warning
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

    LLVMFuzzerTestOneInput_1(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
