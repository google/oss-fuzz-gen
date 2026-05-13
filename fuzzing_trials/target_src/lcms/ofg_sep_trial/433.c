#include <stdint.h>
#include <lcms2.h>

// Fuzzing harness for cmsGetHeaderManufacturer
int LLVMFuzzerTestOneInput_433(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile;
    cmsUInt32Number manufacturer;

    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    hProfile = cmsOpenProfileFromMem((void*)data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function under test
    manufacturer = cmsGetHeaderManufacturer(hProfile);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}