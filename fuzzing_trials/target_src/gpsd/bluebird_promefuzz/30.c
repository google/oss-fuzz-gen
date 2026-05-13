#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
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

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

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
    if (!s) {
        return 0;
    }
    memcpy(s, Data, Size);
    s[Size] = '\0';

    char *host = NULL;
    char *service = NULL;
    char *device = NULL;

    // Call parse_uri_dest

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of parse_uri_dest
    char enqhaplo[1024] = "ywpee";
    parse_uri_dest(enqhaplo, &host, &service, &device);
    // End mutation: Producer.REPLACE_ARG_MUTATOR



    // Call ntrip_parse_url

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of ntrip_parse_url
    ntrip_parse_url(&errout, &ntrip_stream, (const char *)"w");
    // End mutation: Producer.REPLACE_ARG_MUTATOR



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
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nmea_add_checksum to casic_write
        struct gps_device_t gxuznqso;

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nmea_add_checksum to ais_binary_decode
        struct gpsd_errout_t pvnojrkg;
        memset(&pvnojrkg, 0, sizeof(pvnojrkg));
        errout_reset(&pvnojrkg);
        struct ais_t uayyzhtb;

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from errout_reset to gpsd_log


        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of gpsd_log
        gpsd_log(ONCORE_POS_HOLD_MODE_ON, &pvnojrkg, (const char *)"r");
        // End mutation: Producer.REPLACE_ARG_MUTATOR



        // End mutation: Producer.APPEND_MUTATOR

        memset(&uayyzhtb, 0, sizeof(uayyzhtb));


        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of ais_binary_decode

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of ais_binary_decode
        bool ret_ais_binary_decode_qyivk = ais_binary_decode(&pvnojrkg, &uayyzhtb, (const unsigned char *)nmea_buffer, TSIP_ACEIII, NULL);
        // End mutation: Producer.REPLACE_ARG_MUTATOR


        // End mutation: Producer.REPLACE_ARG_MUTATOR


        if (ret_ais_binary_decode_qyivk == 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

        memset(&gxuznqso, 0, sizeof(gxuznqso));
        bool ret_gpsd_next_hunt_setting_udinf = gpsd_next_hunt_setting(&gxuznqso);
        if (ret_gpsd_next_hunt_setting_udinf == 0){
        	return 0;
        }


        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function casic_write with ubx_write
        bool ret_casic_write_dfjxl = ubx_write(&gxuznqso, ALLYSTAR_PACKET, COMMENT_PACKET, (const unsigned char *)nmea_buffer, DEVICE_EOF);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR


        if (ret_casic_write_dfjxl == 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

}

    free(s);
    return 0;
}