// This fuzz driver is generated for library gpsd, aiming to fuzz the following functions:
// ntpshm_link_deactivate at timehint.c:440:6 in gpsd.h
// gpsd_wrap at libgpsd_core.c:2183:6 in gpsd.h
// gpsd_deactivate at libgpsd_core.c:364:6 in gpsd.h
// send_dbus_fix at dbusexport.c:40:6 in gpsd.h
// ntrip_close at net_ntrip.c:1328:6 in gpsd.h
// gpsd_close at serial.c:1270:6 in gpsd.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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

// Dummy implementations of the external functions
void ntpshm_link_deactivate_5(struct gps_device_t *device) {}
void gpsd_wrap_5(struct gps_device_t *device) {}
void gpsd_deactivate_5(struct gps_device_t *device) {}
void send_dbus_fix_5(struct gps_device_t *device) {}
void ntrip_close_5(struct gps_device_t *device) {}
void gpsd_close_5(struct gps_device_t *device) {}

static struct gps_device_t *initialize_device(const uint8_t *Data, size_t Size) {
    struct gps_device_t *device = malloc(sizeof(struct gps_device_t));
    if (device == NULL) {
        return NULL;
    }
    memset(device, 0, sizeof(struct gps_device_t));
    
    // Initialize device with fuzz data
    if (Size > sizeof(device->subtype)) {
        Size = sizeof(device->subtype);
    }
    memcpy(device->subtype, Data, Size);
    
    return device;
}

static void cleanup_device(struct gps_device_t *device) {
    if (device) {
        free(device);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    struct gps_device_t *device = initialize_device(Data, Size);
    if (device == NULL) {
        return 0;
    }

    // Fuzz each target function with the initialized device
    ntpshm_link_deactivate_5(device);
    gpsd_wrap_5(device);
    gpsd_deactivate_5(device);
    send_dbus_fix_5(device);
    ntrip_close_5(device);
    gpsd_close_5(device);

    cleanup_device(device);
    return 0;
}