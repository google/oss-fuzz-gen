// This fuzz driver is generated for library gpsd, aiming to fuzz the following functions:
// parse_uri_dest at libgpsd_core.c:471:5 in gpsd.h
// ntrip_parse_url at net_ntrip.c:876:5 in gpsd.h
// netlib_errstr at netlib.c:260:13 in gpsd.h
// nmea_add_checksum at driver_nmea0183.c:6842:6 in gpsd.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
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

static void dummy_report(const char *message) {
    // Dummy report function
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy gpsd_errout_t
    struct gpsd_errout_t errout;
    errout.debug = 0;
    errout.report = dummy_report;
    errout.label = "fuzz";

    // Prepare dummy ntrip_stream_t
    struct ntrip_stream_t ntrip_stream;
    memset(&ntrip_stream, 0, sizeof(ntrip_stream));

    // Prepare buffers for parse_uri_dest
    char *s = (char *)malloc(Size + 1);
    if (!s) return 0;
    memcpy(s, Data, Size);
    s[Size] = '\0';

    char *host = NULL;
    char *service = NULL;
    char *device = NULL;

    // Call parse_uri_dest
    parse_uri_dest(s, &host, &service, &device);

    // Call ntrip_parse_url
    ntrip_parse_url(&errout, &ntrip_stream, s);

    // Call netlib_errstr
    if (Size > 0) {
        int err_code = Data[0];
        const char *errstr = netlib_errstr(err_code);
        (void)errstr;
    }

    // Prepare buffer for nmea_add_checksum
    if (Size + 6 < 1024) {
        char nmea_buffer[1024];
        memcpy(nmea_buffer, Data, Size);
        nmea_buffer[Size] = '\0';
        nmea_add_checksum(nmea_buffer);
    }

    free(s);
    return 0;
}