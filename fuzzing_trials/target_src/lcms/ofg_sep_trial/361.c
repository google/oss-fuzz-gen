#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_361(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIELab) * 2) {
        return 0;
    }

    cmsCIELab lab1;
    cmsCIELab lab2;

    // Ensure the data is large enough to populate both cmsCIELab structures
    const cmsCIELab *input1 = (const cmsCIELab *)data;
    const cmsCIELab *input2 = (const cmsCIELab *)(data + sizeof(cmsCIELab));

    // Copy the data into the cmsCIELab structures
    lab1.L = input1->L;
    lab1.a = input1->a;
    lab1.b = input1->b;

    lab2.L = input2->L;
    lab2.a = input2->a;
    lab2.b = input2->b;

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsDeltaE(&lab1, &lab2);

    // Use the result in some way to avoid compiler optimizations
    volatile cmsFloat64Number result = deltaE;
    (void)result;

    return 0;
}