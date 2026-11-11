#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    cmsHTRANSFORM handle;
    cmsCIELab cielab;

    // Ensure that size is sufficient to extract cmsCIELab values
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize the cmsCIELab structure from the input data
    cielab.L = *((double*)data);
    cielab.a = *((double*)(data + sizeof(double)));
    cielab.b = *((double*)(data + 2 * sizeof(double)));

    // Create a dummy handle for testing purposes
    handle = cmsCreateTransform(NULL, TYPE_Lab_DBL, NULL, TYPE_Lab_DBL, INTENT_PERCEPTUAL, 0);
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsGDBCheckPoint(handle, &cielab);

    // Clean up
    cmsDeleteTransform(handle);

    return 0;
}