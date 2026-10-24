#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Initialize variables for the function-under-test
    tjhandle handle = tjInitCompress();
    int param1 = 0;
    int param2 = 0;

    // Ensure that the handle is not NULL
    if (handle == NULL) {
        return 0;
    }

    // Use the input data to set the parameters
    if (size >= 2) {
        param1 = static_cast<int>(data[0]);
        param2 = static_cast<int>(data[1]);
    }

    // Call the function-under-test
    tj3Set(handle, param1, param2);

    // Clean up
    tjDestroy(handle);

    return 0;
}