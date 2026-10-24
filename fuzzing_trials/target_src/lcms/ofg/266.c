#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_266(const uint8_t *data, size_t size) {
    if (size < 6 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    cmsCIELab lab1, lab2;
    cmsFloat64Number l, c;

    // Initialize cmsCIELab structures from input data
    lab1.L = ((cmsFloat64Number *)data)[0];
    lab1.a = ((cmsFloat64Number *)data)[1];
    lab1.b = ((cmsFloat64Number *)data)[2];

    lab2.L = ((cmsFloat64Number *)data)[3];
    lab2.a = ((cmsFloat64Number *)data)[4];
    lab2.b = ((cmsFloat64Number *)data)[5];

    // Set l and c to some constant values for fuzzing
    l = 2.0;
    c = 1.0;

    // Call the function-under-test
    cmsFloat64Number result = cmsCMCdeltaE(&lab1, &lab2, l, c);

    // Use the result in some way to avoid compiler optimizations
    volatile cmsFloat64Number use_result = result;
    (void)use_result;

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

    LLVMFuzzerTestOneInput_266(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
