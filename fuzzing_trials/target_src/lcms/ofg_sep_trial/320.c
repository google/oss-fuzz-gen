#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>  // Include the Little CMS library header

// Remove the extern "C" linkage specification for C++ compatibility
int LLVMFuzzerTestOneInput_320(const uint8_t *data, size_t size) {
    // Declare and initialize a cmsContext variable
    cmsContext context = cmsCreateContext(NULL, NULL);  // Create a valid context

    if (context != NULL) {
        // Call the function-under-test
        cmsDeleteContext(context);
    }

    return 0;
}