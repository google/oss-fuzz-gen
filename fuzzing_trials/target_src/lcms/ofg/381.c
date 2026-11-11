#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_381(const uint8_t *data, size_t size) {
    // Ensure we have enough data to fill two cmsCIELab structures
    if (size < 2 * sizeof(cmsCIELab)) {
        return 0;
    }

    // Cast the input data to cmsCIELab pointers
    const cmsCIELab *lab1 = (const cmsCIELab *)data;
    const cmsCIELab *lab2 = (const cmsCIELab *)(data + sizeof(cmsCIELab));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsDeltaE(lab1, lab2);

    // Use deltaE in some way to prevent it from being optimized out
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

    LLVMFuzzerTestOneInput_381(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
