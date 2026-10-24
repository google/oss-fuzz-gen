#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for cmsHPROFILE and cmsUInt32Number
    if (size < sizeof(cmsHPROFILE) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile;
    cmsUInt32Number index;

    // Extract cmsHPROFILE and cmsUInt32Number from the input data
    // Assuming cmsHPROFILE can be interpreted from the first part of data
    // and cmsUInt32Number from the subsequent part
    hProfile = (cmsHPROFILE)(uintptr_t)data; // Cast data to cmsHPROFILE
    index = *(cmsUInt32Number *)(data + sizeof(cmsHPROFILE));

    // Call the function-under-test
    cmsTagSignature tagSignature = cmsGetTagSignature(hProfile, index);

    // Optionally, you can perform additional operations or checks on tagSignature

    return 0;
}