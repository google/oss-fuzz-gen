#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize the tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;
    }

    // Ensure the size is not zero to avoid invalid memory access
    if (size < sizeof(int)) {
        tjDestroy(handle);
        return 0;
    }

    // Use the first byte of data as an integer parameter for tj3Get
    int param = static_cast<int>(data[0]);

    // Call the function-under-test
    int result = tj3Get(handle, param);

    // Clean up
    tjDestroy(handle);

    return 0;
}