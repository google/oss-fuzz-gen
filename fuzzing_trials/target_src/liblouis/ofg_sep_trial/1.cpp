#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t

extern "C" {
    #include <liblouis/liblouis.h>
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Since lou_logEnd() does not take any parameters and does not return any value,
    // we simply call the function to fuzz it.
    lou_logEnd();
    
    return 0;
}