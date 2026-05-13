#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIELab lab1, lab2;
    cmsFloat64Number param1, param2, param3;

    // Ensure size is sufficient to extract required data
    if (size < sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 3) {
        return 0;
    }

    // Initialize cmsCIELab structures
    lab1.L = *(cmsFloat64Number *)(data);
    lab1.a = *(cmsFloat64Number *)(data + sizeof(cmsFloat64Number));
    lab1.b = *(cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number));

    lab2.L = *(cmsFloat64Number *)(data + 3 * sizeof(cmsFloat64Number));
    lab2.a = *(cmsFloat64Number *)(data + 4 * sizeof(cmsFloat64Number));
    lab2.b = *(cmsFloat64Number *)(data + 5 * sizeof(cmsFloat64Number));

    // Initialize cmsFloat64Number parameters
    param1 = *(cmsFloat64Number *)(data + 6 * sizeof(cmsFloat64Number));
    param2 = *(cmsFloat64Number *)(data + 7 * sizeof(cmsFloat64Number));
    param3 = *(cmsFloat64Number *)(data + 8 * sizeof(cmsFloat64Number));

    // Call the function-under-test
    cmsFloat64Number result = cmsCIE2000DeltaE(&lab1, &lab2, param1, param2, param3);

    // Use the result to prevent compiler optimizations (optional)
    (void)result;

    return 0;
}