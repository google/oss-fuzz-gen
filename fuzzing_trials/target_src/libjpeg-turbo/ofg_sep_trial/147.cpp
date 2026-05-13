#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

// Fuzzing harness for tjFree function
extern "C" int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Allocate memory for the input data
    unsigned char *buffer = static_cast<unsigned char*>(malloc(size + 1));
    if (buffer == nullptr) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data into the buffer and ensure it's null-terminated
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Call the function-under-test
    tjFree(buffer);

    // No need to free the buffer manually as tjFree is expected to handle it
    return 0;
}