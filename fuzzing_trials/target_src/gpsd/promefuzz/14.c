// This fuzz driver is generated for library gpsd, aiming to fuzz the following functions:
// shm_release at shmexport.c:111:6 in gpsd.h
// shm_update at shmexport.c:140:6 in gpsd.h
// gpsd_zero_satellites at libgpsd_core.c:2194:6 in gpsd.h
// ntpshm_context_init at timehint.c:154:6 in gpsd.h
// gps_context_init at libgpsd_core.c:299:6 in gpsd.h
// gpsd_init at libgpsd_core.c:314:6 in gpsd.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
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

// Mock implementations for the external functions
void shm_release(struct gps_context_t *context) {
    // Mock implementation
}

void shm_update(struct gps_context_t *context, struct gps_data_t *gps_data) {
    // Mock implementation
}

void gpsd_init_14(struct gps_device_t *device, struct gps_context_t *context, const char *data) {
    // Mock implementation
}

void gps_context_init_14(struct gps_context_t *context, const char *label) {
    // Mock implementation
}

void gpsd_zero_satellites_14(struct gps_data_t *sp) {
    // Mock implementation
}

void ntpshm_context_init(struct gps_context_t *context) {
    // Mock implementation
}

static void initialize_gps_context(struct gps_context_t *context) {
    memset(context, 0, sizeof(struct gps_context_t));
    context->valid = LEAP_SECOND_VALID | GPS_TIME_VALID | CENTURY_VALID;
    context->readonly = false;
    context->passive = false;
    context->batteryRTC = false;
    context->fixed_port_speed = 0;
    strcpy(context->fixed_port_framing, "");
    context->fixcnt = 0;
    context->start_time = time(NULL);
    context->leap_seconds = 18;
    context->gps_week = 2045;
    context->gps_tow.tv_sec = 0;
    context->gps_tow.tv_nsec = 0;
    context->century = 21;
    context->rollovers = 0;
    context->leap_notify = LEAP_NOWARNING;
}

static void initialize_gps_data(struct gps_data_t *data) {
    memset(data, 0, sizeof(struct gps_data_t));
    data->set = ONLINE_SET | TIME_SET | LATLON_SET;
    data->fix.mode = MODE_3D;
    data->fix.status = STATUS_GPS;
    data->fix.latitude = 37.7749;
    data->fix.longitude = -122.4194;
    data->fix.altHAE = 10.0;
    data->fix.epx = 5.0;
    data->fix.epy = 5.0;
    data->fix.epv = 10.0;
    data->satellites_used = 8;
    data->satellites_visible = 12;
}

static void initialize_gps_device(struct gps_device_t *device, struct gps_context_t *context) {
    memset(device, 0, sizeof(struct gps_device_t));
    device->context = context;
    strcpy(device->subtype, "Test subtype");
    device->gpsdata.fix.mode = MODE_3D;
    device->gpsdata.fix.status = STATUS_GPS;
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct gps_context_t context;
    struct gps_data_t gps_data;
    struct gps_device_t gps_device;
    
    initialize_gps_context(&context);
    initialize_gps_data(&gps_data);
    initialize_gps_device(&gps_device, &context);

    // Fuzz gps_context_init
    gps_context_init_14(&context, (const char *)Data);

    // Fuzz gpsd_init
    gpsd_init_14(&gps_device, &context, (const char *)Data);

    // Fuzz shm_release
    shm_release(&context);

    // Fuzz shm_update
    shm_update(&context, &gps_data);

    // Fuzz gpsd_zero_satellites
    gpsd_zero_satellites_14(&gps_data);

    // Fuzz ntpshm_context_init
    ntpshm_context_init(&context);

    return 0;
}