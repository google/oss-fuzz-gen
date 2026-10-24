#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Function to create a dummy cmsToneCurve for testing purposes
cmsToneCurve* createDummyToneCurve() {
    // Create a tone curve with a single segment
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Example gamma value
    return toneCurve;
}

int LLVMFuzzerTestOneInput_400(const uint8_t *data, size_t size) {
    // Create a dummy tone curve for testing
    cmsToneCurve* inputToneCurve = createDummyToneCurve();
    if (inputToneCurve == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsToneCurve *reversedToneCurve = cmsReverseToneCurve(inputToneCurve);

    // Clean up the dummy tone curve
    cmsFreeToneCurve(inputToneCurve);

    // Clean up if a valid tone curve was returned
    if (reversedToneCurve != NULL) {
        cmsFreeToneCurve(reversedToneCurve);
    }

    return 0;
}