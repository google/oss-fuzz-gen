// This fuzz driver is generated for library gpsd, aiming to fuzz the following functions:
// gpsd_init at libgpsd_core.c:314:6 in gpsd.h
// netgnss_report at net_gnss_dispatch.c:92:6 in gpsd.h
// ntrip_report at net_ntrip.c:1271:6 in gpsd.h
// gpsd_assert_sync at serial.c:1253:6 in gpsd.h
// dgpsip_report at net_dgpsip.c:85:6 in gpsd.h
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
    if (!device) return;
    memset(device, 0, sizeof(struct gps_device_t));
    device->gpsdata.gps_fd = -1;
}

static void initialize_gps_context(struct gps_context_t *context) {
    if (!context) return;
    memset(context, 0, sizeof(struct gps_context_t));
    context->errout.debug = 0;
    context->errout.report = NULL;
    context->errout.label = NULL;
    context->leap_notify = LEAP_NOWARNING;
#ifdef SHM_EXPORT_ENABLE
    context->shmexport = NULL;
    context->shmid = -1;
#endif
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct gps_device_t) + sizeof(struct gps_context_t) + 1) {
        return 0; // Not enough data for meaningful fuzzing
    }

    struct gps_device_t device1, device2, device3;
    struct gps_context_t context;

    initialize_gps_device(&device1);
    initialize_gps_device(&device2);
    initialize_gps_device(&device3);
    initialize_gps_context(&context);

    const char *dummy_string = (const char *)(Data + sizeof(struct gps_device_t) + sizeof(struct gps_context_t));
    
    // Fuzz gpsd_init
    gpsd_init(&device1, &context, dummy_string);

    // Fuzz other functions with initialized data
    netgnss_report(&context, &device1, &device2);
    ntrip_report(&context, &device1, &device2);
    gpsd_assert_sync(&device1);
    dgpsip_report(&context, &device1, &device2);
    // Commenting out ntpshm_session_init as it seems to be missing
    // ntpshm_session_init(&device1);

    return 0;
}