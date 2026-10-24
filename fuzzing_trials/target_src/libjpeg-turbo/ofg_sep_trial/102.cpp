#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <cstring> // Include for memcpy

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    // Function-under-test
    void tj3Free(void *buffer);
}

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Allocate a non-null buffer to pass to tj3Free
    void *buffer = malloc(size > 0 ? size : 1); // Ensure size is at least 1 to avoid NULL allocation

    // Fill the buffer with the fuzzer data
    if (buffer != NULL && size > 0) {
        memcpy(buffer, data, size);
    }

    // Call the function-under-test
    tj3Free(buffer);

    return 0;
}