#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_231(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to fill a cmsCIExyY structure
    if (size < sizeof(cmsCIExyY)) {
        return 0;
    }

    // Cast the input data to a cmsCIExyY pointer
    const cmsCIExyY *ciexyY = (const cmsCIExyY *)data;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLab4Profile(ciexyY);

    // If a profile was created, release it
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}