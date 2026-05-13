#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h> // Include the Little CMS library header

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context;
    void *userData;

    // Ensure the data size is sufficient to create a context
    if (size < sizeof(cmsContext)) {
        return 0;
    }

    // Initialize the context with some non-NULL value
    context = (cmsContext)data; // Cast the data to cmsContext for testing

    // Call the function-under-test
    userData = cmsGetContextUserData(context);

    // Optionally, you can add checks or further processing on userData

    return 0; // Return 0 to indicate successful execution
}