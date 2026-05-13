#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>  // Include the Little CMS library header

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsIOHANDLER *ioHandler = NULL;

    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a memory-based profile from the input data
    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;  // Return if profile creation fails
    }

    // Call the function-under-test
    ioHandler = cmsGetProfileIOhandler(hProfile);

    // Clean up
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}