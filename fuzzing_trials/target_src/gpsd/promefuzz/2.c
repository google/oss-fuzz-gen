// This fuzz driver is generated for library gpsd, aiming to fuzz the following functions:
// gpsd_tty_init at serial.c:371:6 in gpsd.h
// gpsd_wrap at libgpsd_core.c:2183:6 in gpsd.h
// gpsd_set_century at timebase.c:255:6 in gpsd.h
// gpsd_close at serial.c:1270:6 in gpsd.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <termios.h>
#include <pthread.h>
#include "gpsd_config.h"
#include "gpsd_config.h"
#include "gpsd_config.h"
#include "gpsd.h"
#include "gpsd.h"
#include "gpsd_config.h"
#include "gpsd.h"
#include "gpsd.h"
#include "gpsd_config.h"
#include "gpsd_config.h"
#include "gpsd.h"
#include "gpsd.h"
#include "gpsd_config.h"
#include "gpsd.h"
#include "gpsd.h"

static void initialize_gps_device(struct gps_device_t *device) {
    memset(device, 0, sizeof(struct gps_device_t));
    device->gpsdata.set = ONLINE_SET;
    device->gpsdata.fix.mode = MODE_NO_FIX;
    device->gpsdata.fix.status = STATUS_UNK;
    device->gpsdata.fix.latitude = NAN;
    device->gpsdata.fix.longitude = NAN;
    device->gpsdata.fix.altitude = NAN;
    device->gpsdata.fix.altHAE = NAN;
    device->gpsdata.fix.altMSL = NAN;
    device->gpsdata.fix.track = NAN;
    device->gpsdata.fix.speed = NAN;
    device->gpsdata.fix.climb = NAN;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct gps_device_t)) {
        return 0;
    }

    struct gps_device_t device;
    initialize_gps_device(&device);

    gpsd_tty_init(&device);
    
    // Assuming event_wakeup and event_driver_switch are defined elsewhere
    // Use integer literals or define them appropriately
    const int event_wakeup = 0; // Placeholder value
    const int event_driver_switch = 1; // Placeholder value

    // Check if the function pointer is not null before calling
    if (device.device_type && device.device_type->event_hook) {
        device.device_type->event_hook(&device, event_wakeup);
    }

    gpsd_wrap(&device);
    gpsd_set_century(&device);

    // Check if the function pointer is not null before calling
    if (device.device_type && device.device_type->event_hook) {
        device.device_type->event_hook(&device, event_driver_switch);
    }
    
    gpsd_close(&device);

    return 0;
}