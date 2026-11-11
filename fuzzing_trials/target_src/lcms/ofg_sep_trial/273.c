#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Define a simple log error handler function
void myLogErrorHandler_273(cmsContext contextId, cmsUInt32Number errorCode, const char *text) {
    // Just print the error message
    (void)contextId; // Unused parameter
    (void)errorCode; // Unused parameter
    (void)text;      // Unused parameter
}

int LLVMFuzzerTestOneInput_273(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    
    // Ensure the context is not NULL
    if (context == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsSetLogErrorHandlerTHR(context, myLogErrorHandler_273);

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}