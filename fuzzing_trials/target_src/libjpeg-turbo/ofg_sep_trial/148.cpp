#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero to allocate memory
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input data
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == nullptr) {
        return 0;
    }

    // Copy data into the buffer
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = data[i];
    }

    // Call the function-under-test
    tjFree(buffer);

    return 0;
}