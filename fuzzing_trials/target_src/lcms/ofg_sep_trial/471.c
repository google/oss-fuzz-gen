#include <stdint.h>
#include <stddef.h>  // Include this for size_t
#include <lcms2.h>   // Include the Little CMS header for cmsUnregisterPlugins

// Function prototype for the function-under-test
void cmsUnregisterPlugins();

int LLVMFuzzerTestOneInput_471(const uint8_t *data, size_t size) {
    // Call the function-under-test
    cmsUnregisterPlugins();

    return 0;
}