#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "gpsd_config.h"  // Include the configuration header for GPSD
#include "gpsd.h"

// Ensure MAX_DEVICES is defined if not already
#ifndef MAX_DEVICES
#define MAX_DEVICES 4  // Define a reasonable default if not provided
#endif

// Use 'extern "C"' only if compiling with a C++ compiler
#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    struct gps_device_t gps_device;
    char buffer[256];  // Assuming a reasonable size for the buffer

    // Initialize gps_device with non-null values
    memset(&gps_device, 0, sizeof(gps_device));

    // Ensure the buffer is not null and has some initial content
    memset(buffer, 'A', sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Use the fuzzer input data to simulate realistic input for the function
    if (size > 0) {
        // Copy the fuzzer input into the buffer, ensuring no overflow
        size_t copy_size = size < sizeof(buffer) ? size : sizeof(buffer) - 1;
        memcpy(buffer, data, copy_size);
        buffer[copy_size] = '\0';  // Null-terminate the buffer

        // Optionally, initialize gps_device fields with fuzzer input
        // Example: gps_device.some_field = data[0]; // if applicable

        // Call the function-under-test with the modified buffer
        gpsd_position_fix_dump(&gps_device, buffer, sizeof(buffer));
    }

    return 0;
}

#ifdef __cplusplus
}
#endif