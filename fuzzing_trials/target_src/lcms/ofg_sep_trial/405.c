#include <stdint.h>
#include <stdlib.h>
#include <lcms2_plugin.h>

int LLVMFuzzerTestOneInput_405(const uint8_t *data, size_t size) {
    // Ensure that the data is large enough to be used as a context
    if (size < sizeof(cmsContext)) {
        return 0; // Not enough data to form a valid cmsContext
    }

    cmsContext context = (cmsContext)data; // Cast data to cmsContext for testing

    // Call the function-under-test
    cmsHANDLE handle = cmsIT8Alloc(context);

    // Normally, you would do something with 'handle' here, like checking its validity
    // or performing additional operations. For fuzzing, we just need to ensure the function is called.

    // Clean up if necessary
    if (handle != NULL) {
        cmsIT8Free(handle);
    }

    return 0;
}