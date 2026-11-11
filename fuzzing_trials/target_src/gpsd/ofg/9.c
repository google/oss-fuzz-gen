#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>          // Include the time library for struct timespec
#include "gpsd_config.h"   // Include the configuration header for GPSD
#include "gpsd.h"          // Include the main GPSD header

// Define MAX_DEVICES if it's not defined in the included headers
#ifndef MAX_DEVICES
#define MAX_DEVICES 4
#endif

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Ensure there is enough data to perform meaningful operations
    if (size < sizeof(struct gps_fix_t) + sizeof(struct timespec)) {
        return 0;
    }

    // Declare and initialize the necessary structures
    struct gps_device_t gps_device;
    struct timedelta_t timedelta;

    // Initialize the gps_device structure with data from the input
    gps_device.gpsdata.online.tv_sec = ((struct timespec *)data)->tv_sec;
    gps_device.gpsdata.online.tv_nsec = ((struct timespec *)data)->tv_nsec;
    gps_device.gpsdata.fix.mode = ((struct gps_fix_t *)(data + sizeof(struct timespec)))->mode;

    // Initialize the timedelta structure with data from the input
    timedelta.real.tv_sec = ((struct timespec *)(data + sizeof(struct gps_fix_t)))->tv_sec;
    timedelta.real.tv_nsec = ((struct timespec *)(data + sizeof(struct gps_fix_t)))->tv_nsec;
    timedelta.clock.tv_sec = ((struct timespec *)(data + sizeof(struct gps_fix_t) + sizeof(struct timespec)))->tv_sec;
    timedelta.clock.tv_nsec = ((struct timespec *)(data + sizeof(struct gps_fix_t) + sizeof(struct timespec)))->tv_nsec;

    // Call the function-under-test
    ntp_latch(&gps_device, &timedelta);

    return 0;
}