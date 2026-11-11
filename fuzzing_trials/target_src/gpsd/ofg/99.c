#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for memcpy and memset

// Include the configuration header for GPSD
#include "gpsd_config.h"
#include "gpsd.h"

// Remove the redefinition of MAX_DEVICES, as it is already defined in gpsd_config.h

// Use 'extern "C"' only in C++ to prevent name mangling
#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Declare and initialize structures
    struct gps_context_t context;
    struct gps_device_t device1;
    struct gps_device_t device2;

    // Initialize the structures with some non-NULL values
    // For fuzzing purposes, we can use some data from the input buffer
    if (size >= sizeof(struct gps_context_t) + 2 * sizeof(struct gps_device_t)) {
        // Copy data into the structures
        memcpy(&context, data, sizeof(struct gps_context_t));
        memcpy(&device1, data + sizeof(struct gps_context_t), sizeof(struct gps_device_t));
        memcpy(&device2, data + sizeof(struct gps_context_t) + sizeof(struct gps_device_t), sizeof(struct gps_device_t));
    } else {
        // If input data is insufficient, initialize with default values
        memset(&context, 0, sizeof(struct gps_context_t));
        memset(&device1, 0, sizeof(struct gps_device_t));
        memset(&device2, 0, sizeof(struct gps_device_t));
    }

    // Call the function-under-test
    ntrip_report(&context, &device1, &device2);

    return 0;
}

#ifdef __cplusplus
}
#endif