#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_193(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 3) {
        return 0; // Not enough data to fill all parameters
    }

    // Initialize cmsCIELab structures
    cmsCIELab lab1, lab2;

    // Copy data into cmsCIELab structures
    const cmsCIELab* lab1_ptr = (const cmsCIELab*) data;
    const cmsCIELab* lab2_ptr = (const cmsCIELab*) (data + sizeof(cmsCIELab));

    // Extract cmsFloat64Number values
    const cmsFloat64Number* kL = (const cmsFloat64Number*) (data + sizeof(cmsCIELab) * 2);
    const cmsFloat64Number* kC = (const cmsFloat64Number*) (data + sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number));
    const cmsFloat64Number* kH = (const cmsFloat64Number*) (data + sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 2);

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCIE2000DeltaE(lab1_ptr, lab2_ptr, *kL, *kC, *kH);

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

    LLVMFuzzerTestOneInput_193(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
