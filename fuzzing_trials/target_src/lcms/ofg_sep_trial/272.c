#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Define a custom log error handler function
void customLogErrorHandler(cmsContext context, cmsUInt32Number errorCode, const char *text) {
    // Custom error handling logic (e.g., logging to a file or console)
    (void)context; // Suppress unused variable warning
    (void)errorCode; // Suppress unused variable warning
    (void)text; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_272(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsContext)) {
        return 0; // Not enough data to form a valid cmsContext
    }

    cmsContext context = (cmsContext)(uintptr_t)data; // Cast data to cmsContext
    cmsLogErrorHandlerFunction logErrorHandler = customLogErrorHandler;

    // Call the function-under-test
    cmsSetLogErrorHandlerTHR(context, logErrorHandler);

    return 0;
}