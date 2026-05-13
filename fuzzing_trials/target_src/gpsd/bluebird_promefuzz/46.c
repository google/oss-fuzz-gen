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

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
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

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of nmea_add_checksum
        char ktuajsja[1024] = "dvgfh";
        nmea_add_checksum(ktuajsja);
        // End mutation: Producer.REPLACE_ARG_MUTATOR


    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nmea_add_checksum to casic_write
        struct gps_device_t gxuznqso;

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nmea_add_checksum to ais_binary_decode
        struct gpsd_errout_t pvnojrkg;

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nmea_add_checksum to gpsd_init
        struct gps_device_t nhfkrcza;
        memset(&nhfkrcza, 0, sizeof(nhfkrcza));
        gpsd_set_century(&nhfkrcza);
        struct gps_context_t hsxrsoir;
        memset(&hsxrsoir, 0, sizeof(hsxrsoir));

        gpsd_init(&nhfkrcza, &hsxrsoir, nmea_buffer);

        // End mutation: Producer.APPEND_MUTATOR


        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gpsd_init to ntrip_close


        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function ntrip_close with gpsd_close

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gpsd_init to rtcm3_unpack
        struct rtcm3_t ajnhihtb;
        memset(&ajnhihtb, 0, sizeof(ajnhihtb));

        rtcm3_unpack(&hsxrsoir, &ajnhihtb, (const unsigned char *)nmea_buffer);

        // End mutation: Producer.APPEND_MUTATOR


        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gpsd_close with gpsd_set_century

        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gpsd_set_century with gpsd_deactivate
        gpsd_deactivate(&nhfkrcza);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR


        // End mutation: Producer.REPLACE_FUNC_MUTATOR


        // End mutation: Producer.REPLACE_FUNC_MUTATOR



        // End mutation: Producer.APPEND_MUTATOR

        memset(&pvnojrkg, 0, sizeof(pvnojrkg));
        errout_reset(&pvnojrkg);
        struct ais_t uayyzhtb;
        memset(&uayyzhtb, 0, sizeof(uayyzhtb));
        struct ais_type24_queue_t nlfxldug;
        memset(&nlfxldug, 0, sizeof(nlfxldug));

        bool ret_ais_binary_decode_xarbr = ais_binary_decode(&pvnojrkg, &uayyzhtb, (const unsigned char *)nmea_buffer, TSIP_RES_SMTX, &nlfxldug);
        if (ret_ais_binary_decode_xarbr == 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR


        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ais_binary_decode to ais_binary_encode
        char bmiyrtbp[1024] = "robzx";

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ais_binary_decode to ais_binary_encode
        nmea_add_checksum(host);

        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function gpsd_get_speed_old with gpsd_serial_isatty
        int ret_gpsd_get_speed_old_vkpvn = gpsd_serial_isatty(&nhfkrcza);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR


        if (ret_gpsd_get_speed_old_vkpvn < 0){
        	return 0;
        }

        unsigned int ret_ais_binary_encode_lzulz = ais_binary_encode(&uayyzhtb, (unsigned char *)host, ret_gpsd_get_speed_old_vkpvn);
        if (ret_ais_binary_encode_lzulz < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

        nmea_add_checksum(bmiyrtbp);

        unsigned int ret_ais_binary_encode_kjtzj = ais_binary_encode(&uayyzhtb, (unsigned char *)bmiyrtbp, COMMENT_PACKET);
        if (ret_ais_binary_encode_kjtzj < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

        memset(&gxuznqso, 0, sizeof(gxuznqso));
        bool ret_gpsd_next_hunt_setting_udinf = gpsd_next_hunt_setting(&gxuznqso);
        if (ret_gpsd_next_hunt_setting_udinf == 0){
        	return 0;
        }


        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gpsd_next_hunt_setting to gpsd_init
        struct gps_context_t kmpvmrgi;
        memset(&kmpvmrgi, 0, sizeof(kmpvmrgi));

        gpsd_init(&gxuznqso, &kmpvmrgi, ktuajsja);

        // End mutation: Producer.APPEND_MUTATOR

        bool ret_casic_write_dfjxl = casic_write(&gxuznqso, ALLYSTAR_PACKET, COMMENT_PACKET, (const unsigned char *)nmea_buffer, DEVICE_EOF);
        if (ret_casic_write_dfjxl == 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

}

    free(s);
    return 0;
}