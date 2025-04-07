/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    Library of functions to manage a GNSS module (typically GPS) for accurate
    timestamping of packets and synchronisation of gateways.
    A limited set of module brands/models are supported.

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Sylvain Miermont
*/


/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
    #define _XOPEN_SOURCE 600
#else
    #define _XOPEN_SOURCE 500
#endif

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */
#include <stdio.h>      /* printf fprintf */
#include <string.h>     /* memcpy */

#include <time.h>       /* struct timespec */
#include <fcntl.h>      /* open */
#include <termios.h>    /* tcflush */
#include <math.h>       /* modf */

#include <stdlib.h>

#include "loragw_gps.h"

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#if DEBUG_GPS == 1
    #define DEBUG_MSG(args...)  fprintf(stderr, args)
    #define DEBUG_ARRAY(a,b,c)  for(a=0;a<b;++a) fprintf(stderr,"%x.",c[a]);fprintf(stderr,"end\n")
    #define CHECK_NULL(a)       if(a==NULL){fprintf(stderr,"%s:%d: ERROR: NULL POINTER AS ARGUMENT\n", __FUNCTION__, __LINE__);return LGW_GPS_ERROR;}
#else
    #define DEBUG_MSG(args...)
    #define DEBUG_ARRAY(a,b,c)  for(a=0;a!=0;){}
    #define CHECK_NULL(a)       if(a==NULL){return LGW_GPS_ERROR;}
#endif
#define TRACE()         fprintf(stderr, "@ %s %d\n", __FUNCTION__, __LINE__);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#define TS_CPS              1E6 /* count-per-second of the timestamp counter */
#define PLUS_10PPM          1.00001
#define MINUS_10PPM         0.99999
#define DEFAULT_BAUDRATE    B9600

/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES ---------------------------------------------------- */


/* result of the NMEA parsing */
static short gps_yea = 0; /* year (2 or 4 digits) */
static short gps_mon = 0; /* month (1-12) */
static short gps_day = 0; /* day of the month (1-31) */
static short gps_hou = 0; /* hours (0-23) */
static short gps_min = 0; /* minutes (0-59) */
static short gps_sec = 0; /* seconds (0-60)(60 is for leap second) */
static float gps_fra = 0.0; /* fractions of seconds (<1) */
static bool gps_time_ok = false;

static short gps_dla = 0; /* degrees of latitude */
static double gps_mla = 0.0; /* minutes of latitude */
static char gps_ola = 0; /* orientation (N-S) of latitude */
static short gps_dlo = 0; /* degrees of longitude */
static double gps_mlo = 0.0; /* minutes of longitude */
static char gps_olo = 0; /* orientation (E-W) of longitude */
static short gps_alt = 0; /* altitude */
static bool gps_pos_ok = false;

static char gps_mod = 'N'; /* GPS mode (N no fix, A autonomous, D differential) */
static short gps_sat = 0; /* number of satellites used for fix */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

int nmea_checksum(char *nmea_string, int buff_size, char *checksum);

char nibble_to_hexchar(uint8_t a);

bool validate_nmea_checksum(char *serial_buff, int buff_size);

bool match_label(char *s, char *label, int size, char wildcard);

int str_chop(char *s, int buff_size, char separator, int *idx_ary, int max_idx);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

/*
Calculate the checksum for a NMEA string
Skip the first '$' if necessary and calculate checksum until '*' character is
reached (or buff_size exceeded).
Checksum must point to a 2-byte (or more) char array.
Return position of the checksum in the string
*/
int nmea_checksum(char *nmea_string, int buff_size, char *checksum) {
    int i = 0;
    uint8_t check_num = 0;

    /* check input parameters */
    if ((nmea_string == NULL) ||  (checksum == NULL) || (buff_size <= 1)) {
        DEBUG_MSG("Invalid parameters for nmea_checksum\n");
        return -1;
    }

    /* skip the first '$' if necessary */
    if (nmea_string[i] == '$') {
        i += 1;
    }

    /* xor until '*' or max length is reached */
    while (nmea_string[i] != '*') {
        check_num ^= nmea_string[i];
        i += 1;
        if (i >= buff_size) {
            DEBUG_MSG("Maximum length reached for nmea_checksum\n");
            return -1;
        }
    }

    /* Convert checksum value to 2 hexadecimal characters */
    checksum[0] = nibble_to_hexchar(check_num / 16); /* upper nibble */
    checksum[1] = nibble_to_hexchar(check_num % 16); /* lower nibble */

    return i + 1;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

char nibble_to_hexchar(uint8_t a) {
    if (a < 10) {
        return '0' + a;
    } else if (a < 16) {
        return 'A' + (a-10);
    } else {
        return '?';
    }
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/*
Calculate the checksum of a NMEA frame and compare it to the checksum that is
present at the end of it.
Return true if it matches
*/
bool validate_nmea_checksum(char *serial_buff, int buff_size) {
    int checksum_index;
    char checksum[2]; /* 2 characters to calculate NMEA checksum */

    checksum_index = nmea_checksum(serial_buff, buff_size, checksum);

    /* could we calculate a verification checksum ? */
    if (checksum_index < 0) {
        DEBUG_MSG("ERROR: IMPOSSIBLE TO PARSE NMEA SENTENCE\n");
        return false;
    }

    /* check if there are enough char in the serial buffer to read checksum */
    if (checksum_index >= (buff_size - 2)) {
        DEBUG_MSG("ERROR: IMPOSSIBLE TO READ NMEA SENTENCE CHECKSUM\n");
        return false;
    }

    /* check the checksum per se */
    if ((serial_buff[checksum_index] == checksum[0]) && (serial_buff[checksum_index+1] == checksum[1])) {
        return true;
    } else {
        DEBUG_MSG("ERROR: NMEA CHECKSUM %c%c DOESN'T MATCH VERIFICATION CHECKSUM %c%c\n", serial_buff[checksum_index], serial_buff[checksum_index+1], checksum[0], checksum[1]);
        return false;
    }
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/*
Return true if the "label" string (can contain wildcard characters) matches
the begining of the "s" string
*/
bool match_label(char *s, char *label, int size, char wildcard) {
    int i;

    for (i=0; i < size; i++) {
        if (label[i] == wildcard) continue;
        if (label[i] != s[i]) return false;
    }
    return true;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

/*
Chop a string into smaller strings
Replace every separator in the input character buffer by a null character so
that all s[index] are valid strings.
Populate an array of integer 'idx_ary' representing indexes of token in the
string.
buff_size and max_idx are there to prevent segfaults.
Return the number of token found (number of idx_ary filled).
*/
int str_chop(char *s, int buff_size, char separator, int *idx_ary, int max_idx) {
    int i = 0; /* index in the string */
    int j = 0; /* index in the result array */

    if ((s == NULL) || (buff_size < 0) || (separator == 0) || (idx_ary == NULL) || (max_idx < 0)) {
        /* unsafe to do anything */
        return -1;
    }
    if ((buff_size == 0) || (max_idx == 0)) {
        /* nothing to do */
        return 0;
    }
    s[buff_size - 1] = 0; /* add string terminator at the end of the buffer, just to be sure */
    idx_ary[j] = 0;
    j += 1;
    /* loop until string terminator is reached */
    while (s[i] != 0) {
        if (s[i] == separator) {
            s[i] = 0; /* replace separator by string terminator */
            if (j >= max_idx) { /* no more room in the index array */
                return j;
            }
            idx_ary[j] = i+1; /* next token start after replaced separator */
            ++j;
        }
        ++i;
    }
    return j;
}

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS DEFINITION ------------------------------------------ */

int lgw_gps_enable(char *tty_path, char *gps_familly, speed_t target_brate, int *fd_ptr) {
    int i;
    struct termios ttyopt; /* serial port options */
    int gps_tty_dev; /* file descriptor to the serial port of the GNSS module */

    /* check input parameters */
    CHECK_NULL(tty_path);
    CHECK_NULL(fd_ptr);

    /* open TTY device */
    gps_tty_dev = open(tty_path, O_RDWR | O_NOCTTY);
    if (gps_tty_dev <= 0) {
        DEBUG_MSG("ERROR: TTY PORT FAIL TO OPEN, CHECK PATH AND ACCESS RIGHTS\n");
        return LGW_GPS_ERROR;
    }
    *fd_ptr = gps_tty_dev;

    /* manage the different GPS modules families */
    if (gps_familly != NULL) {
        DEBUG_MSG("WARNING: gps_familly parameter ignored for now\n"); // TODO
    }

    /* manage the target bitrate */
    if (target_brate != 0) {
        DEBUG_MSG("WARNING: target_brate parameter ignored for now\n"); // TODO
    }

    /* get actual serial port configuration */
    i = tcgetattr(gps_tty_dev, &ttyopt);
    if (i != 0) {
        DEBUG_MSG("ERROR: IMPOSSIBLE TO GET TTY PORT CONFIGURATION\n");
        return LGW_GPS_ERROR;
    }

    /* update baudrates */
    cfsetispeed(&ttyopt, DEFAULT_BAUDRATE);
    cfsetospeed(&ttyopt, DEFAULT_BAUDRATE);

    /* update terminal parameters */
    ttyopt.c_cflag |= CLOCAL; /* local connection, no modem control */
    ttyopt.c_cflag |= CREAD; /* enable receiving characters */
    ttyopt.c_cflag |= CS8; /* 8 bit frames */
    ttyopt.c_cflag &= ~PARENB; /* no parity */
    ttyopt.c_cflag &= ~CSTOPB; /* one stop bit */
    ttyopt.c_iflag |= IGNPAR; /* ignore bytes with parity errors */
    ttyopt.c_iflag |= ICRNL; /* map CR to NL */
    ttyopt.c_iflag |= IGNCR; /* Ignore carriage return on input */
    ttyopt.c_lflag |= ICANON; /* enable canonical input */

    /* set new serial ports parameters */
    i = tcsetattr(gps_tty_dev, TCSANOW, &ttyopt);
    if (i != 0){
        DEBUG_MSG("ERROR: IMPOSSIBLE TO UPDATE TTY PORT CONFIGURATION\n");
        return LGW_GPS_ERROR;
    }
    tcflush(gps_tty_dev, TCIOFLUSH);

    /* get timezone info */
    tzset();

    /* initialize global variables */
    gps_time_ok = false;
    gps_pos_ok = false;
    gps_mod = 'N';

    return LGW_GPS_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

enum gps_msg lgw_parse_nmea(char *serial_buff, int buff_size) {
    int i, j, k;
    int str_index[30]; /* string index from the string chopping */
    int nb_fields; /* number of strings detected by string chopping */

    /* check input parameters */
    if (serial_buff == NULL) {
        return UNKNOWN;
    }

    /* display received serial data and checksum */
    DEBUG_MSG("Note: parsing NMEA frame> %s", serial_buff);

    /* look for some NMEA sentences in particular */
    if (buff_size < 8) {
        DEBUG_MSG("ERROR: TOO SHORT TO BE A VALID NMEA SENTENCE\n");
        return UNKNOWN;
    } else if (match_label(serial_buff, "$G?RMC", 6, '?')) {
        /*
        NMEA sentence format: $xxRMC,time,status,lat,NS,long,EW,spd,cog,date,mv,mvEW,posMode*cs<CR><LF>
        Valid fix: $GPRMC,083559.34,A,4717.11437,N,00833.91522,E,0.004,77.52,091202,,,A*00
        No fix: $GPRMC,,V,,,,,,,,,,N*00
        */
        if (!validate_nmea_checksum(serial_buff, buff_size)) {
            DEBUG_MSG("Warning: invalid RMC sentence (bad checksum)\n");
            return INVALID;
        }
        nb_fields = str_chop(serial_buff, buff_size, ',', str_index, ARRAY_SIZE(str_index));
        if (nb_fields != 13) {
            DEBUG_MSG("Warning: invalid RMC sentence (number of fields)\n");
            return INVALID;
        }
        /* parse GPS status */
        gps_mod = *(serial_buff + str_index[12]); /* get first character, no need to bother with sscanf */
        if ((gps_mod != 'N') && (gps_mod != 'A') && (gps_mod != 'D')) {
            gps_mod = 'N';
        }
        /* parse complete time */
        i = sscanf(serial_buff + str_index[1], "%2hd%2hd%2hd%4f", &gps_hou, &gps_min, &gps_sec, &gps_fra);
        j = sscanf(serial_buff + str_index[9], "%2hd%2hd%2hd", &gps_day, &gps_mon, &gps_yea);
        if ((i == 4) && (j == 3)) {
            if ((gps_mod == 'A') || (gps_mod == 'D')) {
                gps_time_ok = true;
                DEBUG_MSG("Note: Valid RMC sentence, GPS locked, date: 20%02d-%02d-%02dT%02d:%02d:%06.3fZ\n", gps_yea, gps_mon, gps_day, gps_hou, gps_min, gps_fra + (float)gps_sec);
            } else {
                gps_time_ok = false;
                DEBUG_MSG("Note: Valid RMC sentence, no satellite fix, estimated date: 20%02d-%02d-%02dT%02d:%02d:%06.3fZ\n", gps_yea, gps_mon, gps_day, gps_hou, gps_min, gps_fra + (float)gps_sec);
            }
        } else {
            /* could not get a valid hour AND date */
            gps_time_ok = false;
            DEBUG_MSG("Note: Valid RMC sentence, mode %c, no date\n", gps_mod);
        }
        return NMEA_RMC;
    } else if (match_label(serial_buff, "$G?GGA", 6, '?')) {
        /*
        NMEA sentence format: $xxGGA,time,lat,NS,long,EW,quality,numSV,HDOP,alt,M,sep,M,diffAge,diffStation*cs<CR><LF>
        Valid fix: $GPGGA,092725.00,4717.11399,N,00833.91590,E,1,08,1.01,499.6,M,48.0,M,,*5B
        */
        if (!validate_nmea_checksum(serial_buff, buff_size)) {
            DEBUG_MSG("Warning: invalid GGA sentence (bad checksum)\n");
            return INVALID;
        }
        nb_fields = str_chop(serial_buff, buff_size, ',', str_index, ARRAY_SIZE(str_index));
        if (nb_fields != 15) {
            DEBUG_MSG("Warning: invalid GGA sentence (number of fields)\n");
            return INVALID;
        }
        /* parse number of satellites used for fix */
        sscanf(serial_buff + str_index[7], "%hd", &gps_sat);
        /* parse 3D coordinates */
        i = sscanf(serial_buff + str_index[2], "%2hd%10lf", &gps_dla, &gps_mla);
        gps_ola = *(serial_buff + str_index[3]);
        j = sscanf(serial_buff + str_index[4], "%3hd%10lf", &gps_dlo, &gps_mlo);
        gps_olo = *(serial_buff + str_index[5]);
        k = sscanf(serial_buff + str_index[9], "%hd", &gps_alt);
        if ((i == 2) && (j == 2) && (k == 1) && ((gps_ola=='N')||(gps_ola=='S')) && ((gps_olo=='E')||(gps_olo=='W'))) {
            gps_pos_ok = true;
            DEBUG_MSG("Note: Valid GGA sentence, %d sat, lat %02ddeg %06.3fmin %c, lon %03ddeg%06.3fmin %c, alt %d\n", gps_sat, gps_dla, gps_mla, gps_ola, gps_dlo, gps_mlo, gps_olo, gps_alt);
        } else {
            /* could not get a valid latitude, longitude AND altitude */
            gps_pos_ok = false;
            DEBUG_MSG("Note: Valid GGA sentence, %d sat, no coordinates\n", gps_sat);
        }
        return NMEA_GGA;
    } else {
        DEBUG_MSG("Note: ignored NMEA sentence\n"); /* quite verbose */
        return INVALID;
    }
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_gps_get(struct timespec *utc, struct coord_s *loc, struct coord_s *err) {
    struct tm x;
    time_t y;

    if (utc != NULL) {
        if (!gps_time_ok) {
            DEBUG_MSG("ERROR: NO VALID TIME TO RETURN\n");
            return LGW_GPS_ERROR;
        }
        memset(&x, 0, sizeof(x));
        if (gps_yea < 100) { /* 2-digits year, 20xx */
            x.tm_year = gps_yea + 100; /* 100 years offset to 1900 */
        } else { /* 4-digits year, Gregorian calendar */
            x.tm_year = gps_yea - 1900;
        }
        x.tm_mon = gps_mon - 1; /* tm_mon is [0,11], gps_mon is [1,12] */
        x.tm_mday = gps_day;
        x.tm_hour = gps_hou;
        x.tm_min = gps_min;
        x.tm_sec = gps_sec;
        y = mktime(&x) - timezone; /* need to substract timezone bc mktime assumes time vector is local time */
        if (y == (time_t)(-1)) {
            DEBUG_MSG("ERROR: FAILED TO CONVERT BROKEN-DOWN TIME\n");
            return LGW_GPS_ERROR;
        }
        utc->tv_sec = y;
        utc->tv_nsec = (int32_t)(gps_fra * 1e9);
    }
    if (loc != NULL) {
        if (!gps_pos_ok) {
            DEBUG_MSG("ERROR: NO VALID POSITION TO RETURN\n");
            return LGW_GPS_ERROR;
        }
        loc->lat = ((double)gps_dla + (gps_mla/60.0)) * ((gps_ola == 'N')?1.0:-1.0);
        loc->lon = ((double)gps_dlo + (gps_mlo/60.0)) * ((gps_olo == 'E')?1.0:-1.0);
        loc->alt = gps_alt;
    }
    if (err != NULL) {
        DEBUG_MSG("Warning: localization error processing not implemented yet\n");
        err->lat = 0.0;
        err->lon = 0.0;
        err->alt = 0;
    }

    return LGW_GPS_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_gps_sync(struct tref *ref, uint32_t count_us, struct timespec utc) {
    double cnt_diff; /* internal concentrator time difference (in seconds) */
    double utc_diff; /* UTC time difference (in seconds) */
    double slope; /* time slope between new reference and old reference (for sanity check) */

    bool aber_n0; /* is the update value for synchronization aberrant or not ? */
    static bool aber_min1 = false; /* keep track of whether value at sync N-1 was aberrant or not  */
    static bool aber_min2 = false; /* keep track of whether value at sync N-2 was aberrant or not  */

    CHECK_NULL(ref);

    /* calculate the slope */
    cnt_diff = (double)(count_us - ref->count_us) / (double)(TS_CPS); /* uncorrected by xtal_err */
    utc_diff = (double)(utc.tv_sec - (ref->utc).tv_sec) + (1E-9 * (double)(utc.tv_nsec - (ref->utc).tv_nsec));

    /* detect aberrant points by measuring if slope limits are exceeded */
    if (utc_diff != 0) { // prevent divide by zero
        slope = cnt_diff/utc_diff;
        if ((slope > PLUS_10PPM) || (slope < MINUS_10PPM)) {
            DEBUG_MSG("Warning: correction range exceeded\n");
            aber_n0 = true;
        } else {
            aber_n0 = false;
        }
    } else {
        DEBUG_MSG("Warning: aberrant UTC value for synchronization\n");
        aber_n0 = true;
    }

    /* watch if the 3 latest sync point were aberrant or not */
    if (aber_n0 == false) {
        /* value no aberrant -> sync with smoothed slope */
        ref->systime = time(NULL);
        ref->count_us = count_us;
        ref->utc = utc;
        ref->xtal_err = slope;
        aber_min2 = aber_min1;
        aber_min1 = aber_n0;
        return LGW_GPS_SUCCESS;
    } else if (aber_n0 && aber_min1 && aber_min2) {
        /* 3 successive aberrant values -> sync reset (keep xtal_err) */
        ref->systime = time(NULL);
        ref->count_us = count_us;
        ref->utc = utc;
        /* reset xtal_err only if the present value is out of range */
        if ((ref->xtal_err > PLUS_10PPM) || (ref->xtal_err < MINUS_10PPM)) {
            ref->xtal_err = 1.0;
        }
        DEBUG_MSG("Warning: 3 successive aberrant sync attempts, sync reset\n");
        aber_min2 = aber_min1;
        aber_min1 = aber_n0;
        return LGW_GPS_SUCCESS;
    } else {
        /* only 1 or 2 successive aberrant values -> ignore and return an error */
        aber_min2 = aber_min1;
        aber_min1 = aber_n0;
        return LGW_GPS_ERROR;
    }

    return LGW_GPS_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_cnt2utc(struct tref ref, uint32_t count_us, struct timespec *utc) {
    double delta_sec;
    double intpart, fractpart;
    long tmp;

    CHECK_NULL(utc);
    if ((ref.systime == 0) || (ref.xtal_err > PLUS_10PPM) || (ref.xtal_err < MINUS_10PPM)) {
        DEBUG_MSG("ERROR: INVALID REFERENCE FOR CNT -> UTC CONVERSION\n");
        return LGW_GPS_ERROR;
    }

    /* calculate delta in seconds between reference count_us and target count_us */
    delta_sec = (double)(count_us - ref.count_us) / (TS_CPS * ref.xtal_err);

    /* now add that delta to reference UTC time */
    fractpart = modf (delta_sec , &intpart);
    tmp = ref.utc.tv_nsec + (long)(fractpart * 1E9);
    if (tmp < (long)1E9) { /* the nanosecond part doesn't overflow */
        utc->tv_sec = ref.utc.tv_sec + (time_t)intpart;
        utc->tv_nsec = tmp;
    } else { /* must carry one second */
        utc->tv_sec = ref.utc.tv_sec + (time_t)intpart + 1;
        utc->tv_nsec = tmp - (long)1E9;
    }

    return LGW_GPS_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_utc2cnt(struct tref ref, struct timespec utc, uint32_t *count_us) {
    double delta_sec;

    CHECK_NULL(count_us);
    if ((ref.systime == 0) || (ref.xtal_err > PLUS_10PPM) || (ref.xtal_err < MINUS_10PPM)) {
        DEBUG_MSG("ERROR: INVALID REFERENCE FOR UTC -> CNT CONVERSION\n");
        return LGW_GPS_ERROR;
    }

    /* calculate delta in seconds between reference utc and target utc */
    delta_sec = (double)(utc.tv_sec - ref.utc.tv_sec);
    delta_sec += 1E-9 * (double)(utc.tv_nsec - ref.utc.tv_nsec);

    /* now convert that to internal counter tics and add that to reference counter value */
    *count_us = ref.count_us + (uint32_t)(delta_sec * TS_CPS * ref.xtal_err);

    return LGW_GPS_SUCCESS;
}

/* --- EOF ------------------------------------------------------------------ */
