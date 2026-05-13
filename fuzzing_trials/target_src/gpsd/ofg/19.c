#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of gps_device_t is available in the included headers
#include "gpsd_config.h"  // Include the config header to resolve GPSD_CONFIG_H error
#include "gpsd.h"  // Include the appropriate header for gps_device_t

extern int gpsd_get_speed_old(const struct gps_device_t *);

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Allocate memory for a gps_device_t structure
    struct gps_device_t *device = (struct gps_device_t *)malloc(sizeof(struct gps_device_t));
    if (device == NULL) {
        return 0;  // Return if allocation fails
    }

    // Initialize the gps_device_t structure with non-NULL values
    memset(device, 0, sizeof(struct gps_device_t));

    // Ensure there is some data to copy into the structure
    if (size > 0) {
        // Copy data into the structure, up to the size of the structure
        memcpy(device, data, size < sizeof(struct gps_device_t) ? size : sizeof(struct gps_device_t));
    }

    // Call the function-under-test
    (void)gpsd_get_speed_old(device);  // Use (void) to explicitly ignore the result

    // Free allocated memory
    free(device);

    return 0;
}