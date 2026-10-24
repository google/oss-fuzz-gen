#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
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

static void initialize_gps_device(struct gps_device_t *device, const uint8_t *Data, size_t Size) {
    memset(device, 0, sizeof(struct gps_device_t));
    // Ensure we do not read beyond Data's boundary
    if (Size >= sizeof(struct gps_data_t)) {
        memcpy(&device->gpsdata, Data, sizeof(struct gps_data_t));
    }
}

static void invoke_gpsd_prettydump(struct gps_device_t *device) {
    const char *result = gpsd_prettydump(device);
    if (result) {
        printf("gpsd_prettydump: %s\n", result);
    }
}

static void invoke_gpsd_get_parity(struct gps_device_t *device) {
    char parity = gpsd_get_parity(device);
    printf("gpsd_get_parity: %c\n", parity);
}

static void invoke_nmea_functions(struct gps_device_t *device, const uint8_t *Data, size_t Size) {
    char buffer[256];
    size_t len = Size < sizeof(buffer) ? Size : sizeof(buffer) - 1;
    memcpy(buffer, Data, len);
    buffer[len] = '\0';

    nmea_subframe_dump(device, buffer, len);
    nmea_ais_dump(device, buffer, len);
    nmea_sky_dump(device, buffer, len);
    nmea_tpv_dump(device, buffer, len);
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    struct gps_device_t device;
    initialize_gps_device(&device, Data, Size);

    // Invoke each function with the initialized gps_device_t
    invoke_gpsd_prettydump(&device);
    invoke_gpsd_get_parity(&device);
    invoke_nmea_functions(&device, Data, Size);

    return 0;
}