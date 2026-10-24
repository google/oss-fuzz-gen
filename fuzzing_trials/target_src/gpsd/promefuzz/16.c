// This fuzz driver is generated for library gpsd, aiming to fuzz the following functions:
// garmin_ser_parse at driver_garmin.c:1051:12 in gpsd.h
// nmea_parse at driver_nmea0183.c:6250:12 in gpsd.h
// nmea_subframe_dump at pseudonmea.c:662:6 in gpsd.h
// nmea_ais_dump at pseudonmea.c:673:6 in gpsd.h
// nmea_sky_dump at pseudonmea.c:651:6 in gpsd.h
// nmea_tpv_dump at pseudonmea.c:630:6 in gpsd.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
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
    // Additional initialization can be done here if necessary
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct gps_device_t)) {
        return 0;
    }

    struct gps_device_t device;
    initialize_gps_device(&device);

    // Fuzz garmin_ser_parse
    gps_mask_t mask = garmin_ser_parse(&device);

    // Fuzz nmea_parse
    char *nmea_data = (char *)malloc(Size);
    if (nmea_data) {
        memcpy(nmea_data, Data, Size);
        mask = nmea_parse(nmea_data, &device);
        free(nmea_data);
    }

    // Prepare a buffer for the dump functions
    char dump_buffer[1024];
    size_t dump_size = sizeof(dump_buffer) < Size ? sizeof(dump_buffer) : Size;

    // Fuzz nmea_subframe_dump
    nmea_subframe_dump(&device, dump_buffer, dump_size);

    // Fuzz nmea_ais_dump
    nmea_ais_dump(&device, dump_buffer, dump_size);

    // Fuzz nmea_sky_dump
    nmea_sky_dump(&device, dump_buffer, dump_size);

    // Fuzz nmea_tpv_dump
    nmea_tpv_dump(&device, dump_buffer, dump_size);

    return 0;
}