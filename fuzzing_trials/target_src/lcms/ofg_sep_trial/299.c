#include <stdint.h>
#include <stddef.h>
#include <lcms2.h> // Include the Little CMS library header

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_299(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE hProfile;
    cmsUInt32Number manufacturer;

    // Check if the input size is sufficient to extract a cmsUInt32Number
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a profile using cmsCreate_sRGBProfile
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the input data
    manufacturer = *(const cmsUInt32Number *)data;

    // Call the function-under-test
    cmsSetHeaderManufacturer(hProfile, manufacturer);

    // Close the profile to avoid memory leaks
    cmsCloseProfile(hProfile);

    return 0;
}