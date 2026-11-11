#include <cstdint>
#include <cstdlib>

// Wrap the C headers and functions with extern "C" to ensure proper linkage
extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    // Call the function-under-test
    char *errorStr = tj3GetErrorStr(handle);

    // Check if errorStr is not NULL and do something with it, if needed
    if (errorStr) {
        // For example, just print the error string
        // Note: In a real fuzzing environment, you might want to avoid printing
        // to avoid cluttering the output. This is just for demonstration.
        // printf("Error: %s\n", errorStr);
    }

    tjDestroy(handle);
    return 0;
}