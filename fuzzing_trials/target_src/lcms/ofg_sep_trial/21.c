#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include string.h for memcpy
#include <lcms2.h>   // Include the Little CMS header for the function definition

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Define and initialize the input structures
    cmsCIELCh lch;
    cmsCIELab lab;

    // Ensure the size is sufficient to fill the cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Populate the cmsCIELab structure with data from the input
    // Using memcpy to ensure we do not access out of bounds
    memcpy(&lab, data, sizeof(cmsCIELab));

    // Call the function-under-test
    cmsLab2LCh(&lch, &lab);

    return 0;
}