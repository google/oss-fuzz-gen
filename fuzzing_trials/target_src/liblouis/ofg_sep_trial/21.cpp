#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"  // Include the correct header where lou_setLogLevel is declared
}

// Remove the custom enum definition to avoid conflict with the typedef in the included header

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure there's at least one byte to determine the log level
    if (size < 1) {
        return 0;
    }

    // Map the first byte of data to a log level
    logLevels level = static_cast<logLevels>(data[0] % 5); // Assuming 5 log levels

    // Call the function-under-test
    lou_setLogLevel(level);

    return 0;
}