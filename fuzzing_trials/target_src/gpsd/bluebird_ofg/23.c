#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "gpsd_config.h"  // Include the correct configuration header if available
#include "gpsd.h"         // Assuming this header file contains the declaration for gpsd_prettydump and struct gps_device_t

// Define MAX_DEVICES if it's not defined in the included headers
#ifndef MAX_DEVICES
#define MAX_DEVICES 4  // You may adjust this value based on your requirements
#endif

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Allocate memory for gps_device_t structure
    struct gps_device_t *device = (struct gps_device_t *)malloc(sizeof(struct gps_device_t));
    if (device == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the gps_device_t structure with non-NULL values
    memset(device, 0, sizeof(struct gps_device_t));

    // Use the input data to initialize the device structure in a meaningful way
    // Ensure you don't overflow the structure
    if (size > 0) {
        size_t copy_size = size < sizeof(struct gps_device_t) ? size : sizeof(struct gps_device_t);
        memcpy(device, data, copy_size);
    }

    // Call the function-under-test
    const char *result = gpsd_prettydump(device);

    // Check the result (optional, depending on what you want to do with the result)
    if (result != NULL) {
        // For fuzzing, we don't need to do anything with the result
        // But you could log it or perform additional checks if needed
    }

    // Free the allocated memory
    free(device);

    return 0;
}