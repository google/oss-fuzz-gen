#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memset function
#include "gpsd_config.h" // Include the required GPSD configuration header
#include "gpsd.h"

int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Allocate memory for gps_data_t structure
    struct gps_data_t *gps_data = (struct gps_data_t *)malloc(sizeof(struct gps_data_t));

    // Ensure gps_data is not NULL
    if (gps_data == NULL) {
        return 0;
    }

    // Initialize gps_data with zero values
    memset(gps_data, 0, sizeof(struct gps_data_t));

    // Use the input data to initialize gps_data fields
    // Correctly using the 'error' field in the union as it is a char array of size 256
    if (size > 0) {
        size_t copy_size = size < sizeof(gps_data->error) ? size : sizeof(gps_data->error);
        memcpy(gps_data->error, data, copy_size);
    }

    // Call the function-under-test
    gpsd_zero_satellites(gps_data);

    // Free allocated memory
    free(gps_data);

    return 0;
}