#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"
}

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    int result = lou_charSize();

    // Use the result in some way to avoid compiler optimizations removing the call
    volatile int use_result = result;

    return 0;
}