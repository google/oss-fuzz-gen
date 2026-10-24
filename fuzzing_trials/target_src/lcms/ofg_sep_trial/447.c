#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_447(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a memory block to simulate a profile
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    
    // Check if profile creation was successful
    if (hProfile != NULL) {
        // Call the function-under-test
        cmsBool result = cmsCloseProfile(hProfile);

        // Optionally, you can use the result for further checks
        (void)result; // Suppress unused variable warning
    }

    return 0;
}