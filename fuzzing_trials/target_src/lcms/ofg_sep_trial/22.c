#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Define and initialize variables for cmsCIELab and cmsCIELCh
    cmsCIELab lab;
    cmsCIELCh lch;

    // Ensure we have enough data to fill cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Populate cmsCIELab with data
    lab.L = ((double)data[0]) + ((double)data[1] / 255.0);
    lab.a = ((double)data[2]) - 128.0;
    lab.b = ((double)data[3]) - 128.0;

    // Call the function-under-test
    cmsLab2LCh(&lch, &lab);

    return 0;
}