#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_254(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIELab lab1, lab2;
    cmsFloat64Number L1, a1, b1, L2, a2, b2, l, c;
    
    // Ensure the data size is sufficient to extract values
    if (size < sizeof(cmsFloat64Number) * 8) {
        return 0;
    }

    // Initialize cmsCIELab structures with data
    L1 = *((cmsFloat64Number*)data);
    a1 = *((cmsFloat64Number*)(data + sizeof(cmsFloat64Number)));
    b1 = *((cmsFloat64Number*)(data + 2 * sizeof(cmsFloat64Number)));
    L2 = *((cmsFloat64Number*)(data + 3 * sizeof(cmsFloat64Number)));
    a2 = *((cmsFloat64Number*)(data + 4 * sizeof(cmsFloat64Number)));
    b2 = *((cmsFloat64Number*)(data + 5 * sizeof(cmsFloat64Number)));
    l = *((cmsFloat64Number*)(data + 6 * sizeof(cmsFloat64Number)));
    c = *((cmsFloat64Number*)(data + 7 * sizeof(cmsFloat64Number)));

    lab1.L = L1;
    lab1.a = a1;
    lab1.b = b1;

    lab2.L = L2;
    lab2.a = a2;
    lab2.b = b2;

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCMCdeltaE(&lab1, &lab2, l, c);

    (void)deltaE; // Use the result to avoid unused variable warning

    return 0;
}