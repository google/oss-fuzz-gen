#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h> // For memcpy
#include "gpsd_config.h" // Include the GPSD configuration header
#include "gpsd.h"

// Define MAX_DEVICES if it's not defined in the included headers
#ifndef MAX_DEVICES
#define MAX_DEVICES 4 // This is an assumption; adjust based on actual GPSD configuration
#endif

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to fill the structure
    if (size < sizeof(struct gps_device_t)) {
        return 0;
    }

    // Allocate memory for a gps_device_t structure
    struct gps_device_t *device = (struct gps_device_t *)malloc(sizeof(struct gps_device_t));
    if (device == NULL) {
        return 0;
    }

    // Initialize the gps_device_t structure to ensure it has a valid state
    memset(device, 0, sizeof(struct gps_device_t));

    // Copy data into the gps_device_t structure, but only up to the size of the input
    size_t copy_size = size < sizeof(struct gps_device_t) ? size : sizeof(struct gps_device_t);
    memcpy(device, data, copy_size);

    // Call the function-under-test
    gpsd_next_hunt_setting(device);

    // Clean up
    free(device);

    return 0;
}