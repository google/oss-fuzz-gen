#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_414(const uint8_t *data, size_t size) {
    cmsCIELab lab;
    double L, a, b, factor;

    // Ensure we have enough data to extract values for L, a, b, and factor
    if (size < sizeof(double) * 4) {
        return 0;
    }

    // Initialize cmsCIELab structure
    lab.L = 50.0; // Arbitrary non-zero value
    lab.a = 0.0;
    lab.b = 0.0;

    // Extract doubles from the input data
    L = *((double*)data);
    a = *((double*)(data + sizeof(double)));
    b = *((double*)(data + 2 * sizeof(double)));
    factor = *((double*)(data + 3 * sizeof(double)));

    // Call the function under test
    cmsBool result = cmsDesaturateLab(&lab, L, a, b, factor);

    // Use the result to prevent any compiler optimizations
    (void)result;

    return 0;
}