#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_445(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsContext)) {
        return 0; // Not enough data to form a valid cmsContext
    }

    cmsContext context = (cmsContext)data; // Cast data to cmsContext for testing

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreate_sRGBProfileTHR(context);

    // Clean up if necessary
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}