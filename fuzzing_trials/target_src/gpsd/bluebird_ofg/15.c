#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>        // Include string.h for memcpy
#include "gpsd_config.h"   // Include the GPSD configuration header
#include "gpsd.h"          // Include the GPSD header

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    struct gps_device_t device;

    // Initialize the gps_device_t structure with non-null values
    device.context = (struct gps_context_t *)malloc(sizeof(struct gps_context_t));
    if (device.context == NULL) {
        return 0;  // Exit if memory allocation fails
    }

    // Ensure the data size is sufficient to fill the necessary fields in the gps_device_t structure
    if (size >= sizeof(device)) {
        memcpy(&device, data, sizeof(device));
    } else {
        memset(&device, 0, sizeof(device));  // Zero out the structure if data is insufficient
    }

    // Call the function-under-test
    gpsd_set_century(&device);

    // Clean up
    free(device.context);

    return 0;
}

#ifdef __cplusplus
}
#endif