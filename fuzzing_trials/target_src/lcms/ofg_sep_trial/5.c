#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a cmsCIExyY structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Cast the input data to a cmsCIExyY pointer
    const cmsCIExyY* whitePoint = (const cmsCIExyY*)data;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab2Profile(whitePoint);

    // Clean up the created profile if it was successfully created
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}