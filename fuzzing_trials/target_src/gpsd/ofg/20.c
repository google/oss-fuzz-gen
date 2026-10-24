#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "gpsd_config.h"
#include "gpsd.h"

// Assuming gps_context_init is declared in one of the included headers or needs to be declared
extern void gps_context_init(struct gps_context_t *context, const char *source);

extern gps_mask_t garmintxt_parse(struct gps_device_t *);

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Check if there's enough data to fill a gps_device_t structure
    if (size < sizeof(struct gps_device_t)) {
        return 0;
    }

    // Allocate memory for gps_device_t
    struct gps_device_t *device = (struct gps_device_t *)malloc(sizeof(struct gps_device_t));
    if (device == NULL) {
        return 0;
    }

    // Initialize the device structure with data
    memset(device, 0, sizeof(struct gps_device_t)); // Zero out the structure to ensure clean state
    memcpy(device, data, sizeof(struct gps_device_t));

    // Additional initialization to ensure the function-under-test is effectively invoked
    struct gps_context_t context;
    gps_context_init(&context, "fuzzing");
    device->context = &context;
    device->gpsdata.dev.path[0] = '\0';  // Ensure path is a valid string

    // Ensure device has meaningful data for parsing
    device->gpsdata.dev.baudrate = 4800; // Set a common baud rate
    device->gpsdata.dev.stopbits = 1; // Set a common stopbits value
    device->gpsdata.dev.parity = 'N'; // Set a common parity value

    // Populate the gpsdata with some test data
    // Assuming gpsdata has a buffer or similar structure that garmintxt_parse uses
    if (size > sizeof(struct gps_device_t)) {
        // Copy remaining data into a buffer that garmintxt_parse will parse
        size_t data_size = size - sizeof(struct gps_device_t);
        if (data_size > sizeof(device->gpsdata.dev.hexdata)) {
            data_size = sizeof(device->gpsdata.dev.hexdata);
        }
        memcpy(device->gpsdata.dev.hexdata, data + sizeof(struct gps_device_t), data_size);
    } else {
        // If not enough data, fill with dummy data to ensure parsing
        memset(device->gpsdata.dev.hexdata, 'A', sizeof(device->gpsdata.dev.hexdata));
    }

    // Call the function-under-test
    gps_mask_t result = garmintxt_parse(device);

    // Utilize the result to avoid unused variable warning
    if (result) {
        printf("Parsed successfully with mask: %lu\n", (unsigned long)result);
    }

    // Clean up
    free(device);

    return 0;
}