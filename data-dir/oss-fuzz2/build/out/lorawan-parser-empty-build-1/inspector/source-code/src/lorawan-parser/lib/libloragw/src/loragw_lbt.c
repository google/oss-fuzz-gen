/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    Functions used to handle the Listen Before Talk feature

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Michael Coracin
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */
#include <stdio.h>      /* printf fprintf */
#include <stdlib.h>     /* abs, labs, llabs */

#include "loragw_radio.h"
#include "loragw_aux.h"
#include "loragw_hal.h"
#include "loragw_lbt.h"
#include "loragw_fpga.h"

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#if DEBUG_LBT == 1
    #define DEBUG_MSG(str)                fprintf(stderr, str)
    #define DEBUG_PRINTF(fmt, args...)    fprintf(stderr,"%s:%d: "fmt, __FUNCTION__, __LINE__, args)
    #define CHECK_NULL(a)                if(a==NULL){fprintf(stderr,"%s:%d: ERROR: NULL POINTER AS ARGUMENT\n", __FUNCTION__, __LINE__);return LGW_REG_ERROR;}
#else
    #define DEBUG_MSG(str)
    #define DEBUG_PRINTF(fmt, args...)
    #define CHECK_NULL(a)                if(a==NULL){return LGW_REG_ERROR;}
#endif

#define TX_START_DELAY      1500
#define LBT_TIMESTAMP_MASK  0x007FFC00

/* -------------------------------------------------------------------------- */
/* --- PRIVATE TYPES -------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#define LBT_CHANNEL_FREQ_NB 10      /* Number of LBT channels */
#define LBT_CHANNEL_DELTA   200000  /* frequency delta between LBT channels, in Hz */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES ---------------------------------------------------- */

extern void *lgw_spi_target; /*! generic pointer to the SPI device */
extern uint8_t lgw_spi_mux_mode; /*! current SPI mux mode used */

/* LBT variables shared with loragw_hal module */
bool lbt_enable;
uint8_t lbt_rssi_target = 160; /* -80 dBm */
uint8_t lbt_nb_channel = 6;
uint32_t lbt_first_channel_freq = 863000000;
uint16_t lbt_scan_time_us = 220;

/* LBT local variables */
static uint32_t lbt_end_tx_delay_1ch_us = 400000;
static uint32_t lbt_end_tx_delay_2ch_us = 200000;
static uint32_t lbt_channel_freq[LBT_CHANNEL_FREQ_NB]; /* absolute, in Hz */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS ---------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

/* As given frequencies have been converted from float to integer, some aliasing
issues can appear, so we can't simply check for equality, but have to take some
margin */
bool is_equal_freq(uint32_t a, uint32_t b) {
    int64_t diff;
    int64_t a64 = (int64_t)a;
    int64_t b64 = (int64_t)b;

    /* Calculate the difference */
    diff = llabs(a64 - b64);

    /* Check for acceptable diff range */
    if( diff <= 10000 )
    {
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS DEFINITION ------------------------------------------ */

int lbt_setconf(struct lgw_conf_lbt_s * conf) {
    int i;

    /* Check input parameters */
    if (conf == NULL ) {
        return LGW_LBT_ERROR;
    }

    /* set internal config according to parameters */
    lbt_enable = conf->enable;
    lbt_rssi_target = conf->rssi_target;
    lbt_scan_time_us = conf->scan_time_us;
    lbt_nb_channel = conf->nb_channel;
    lbt_end_tx_delay_1ch_us = conf->tx_delay_1ch_us;
    lbt_end_tx_delay_2ch_us = conf->tx_delay_2ch_us;
    lbt_first_channel_freq = conf->start_freq;

    /* set derivated parameters */
    lbt_channel_freq[0] = lbt_first_channel_freq;
    for (i=1; i<LBT_CHANNEL_FREQ_NB; i++) {
       lbt_channel_freq[i] = lbt_channel_freq[i-1] + LBT_CHANNEL_DELTA;
    }

    DEBUG_MSG("Note: LBT configuration:\n");
    DEBUG_PRINTF("     lbt_enable               %d\n", lbt_enable );
    DEBUG_PRINTF("     lbt_rssi_target          %d\n", lbt_rssi_target );
    DEBUG_PRINTF("     lbt_scan_time_us         %d\n", lbt_scan_time_us );
    DEBUG_PRINTF("     lbt_nb_channel           %d\n", lbt_nb_channel );
    DEBUG_PRINTF("     lbt_end_tx_delay_1ch_us  %d\n", lbt_end_tx_delay_1ch_us );
    DEBUG_PRINTF("     lbt_end_tx_delay_2ch_us  %d\n", lbt_end_tx_delay_2ch_us);
    DEBUG_PRINTF("     lbt_first_channel_freq   %d\n", lbt_first_channel_freq);

    return LGW_LBT_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lbt_setup(uint32_t rf_freq, uint8_t rssi_target, uint16_t scan_time_us, uint8_t nb_channel) {
    int x;
    int32_t val;
    uint8_t spi_speed_div = 31;
    uint16_t t_spi_us = 16*2*(spi_speed_div+1)/32 + 2;
    uint8_t nb_point_calc = scan_time_us/t_spi_us - 1;
    uint8_t pll_lock_time = 50;
    uint16_t lsb_start_freq_int;

    /* Check if LBT feature is supported by FPGA */
    x = lgw_fpga_reg_r(LGW_FPGA_FPGA_FEATURE, &val);
    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to read FPGA Features register\n");
        return LGW_LBT_ERROR;
    }
    if (TAKE_N_BITS_FROM((uint8_t)val, 2, 1) != 1) {
        DEBUG_MSG("ERROR: No support for LBT in FPGA\n");
        return LGW_LBT_ERROR;
    }

    /* Configure SX127x for FSK */
    x = lgw_setup_sx127x(rf_freq, MOD_FSK);
    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to configure SX127x for LBT\n");
        return LGW_LBT_ERROR;
    }

    /* Configure FPGA for LBT */
    x  = lgw_fpga_reg_w(LGW_FPGA_SPI_MASTER_SPEED_DIVIDER, (int32_t)spi_speed_div);
    x |= lgw_fpga_reg_w(LGW_FPGA_NB_READ_RSSI, (int32_t)nb_point_calc);
    x |= lgw_fpga_reg_w(LGW_FPGA_PLL_LOCK_TIME, (int32_t)pll_lock_time);
    x |= lgw_fpga_reg_w(LGW_FPGA_RSSI_TARGET, (int32_t)rssi_target);
    lsb_start_freq_int = (((uint64_t)rf_freq<<19)/(uint64_t)32000000);
    x |= lgw_fpga_reg_w(LGW_FPGA_LSB_START_FREQ, (int32_t)lsb_start_freq_int);
    x |= lgw_fpga_reg_w(LGW_FPGA_LBT_TIMESTAMP_NB_CH, (int32_t)(nb_channel-1));
    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to configure FPGA for LBT\n");
        return LGW_LBT_ERROR;
    }

    return LGW_LBT_SUCCESS;

}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lbt_start(void) {
    int x;

    x = lgw_fpga_reg_w(LGW_FPGA_CTRL_FEATURE_START, 1);
    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to start LBT FSM\n");
        return LGW_LBT_ERROR;
    }

    return LGW_LBT_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lbt_is_channel_free(struct lgw_pkt_tx_s * pkt_data, bool * tx_allowed) {
    int i;
    int32_t val;
    uint32_t tx_start_time = 0;
    uint32_t tx_end_time = 0;
    uint32_t delta_time = 0;
    uint32_t sx1301_time = 0;
    uint32_t fpga_time = 0;
    uint32_t lbt_time = 0;
    uint32_t lbt_time1 = 0;
    uint32_t lbt_time2 = 0;
    uint32_t tx_max_time = 0;
    int lbt_channel_decod_1 = -1;
    int lbt_channel_decod_2 = -1;
    uint32_t packet_duration = 0;

    /* Check input parameters */
    if ((pkt_data == NULL) || (tx_allowed == NULL)) {
        return LGW_LBT_ERROR;
    }

    /* Check if TX is allowed */
    if (lbt_enable == true) {
        /* TX allowed for LoRa only */
        if (pkt_data->modulation != MOD_LORA) {
            *tx_allowed = false;
            DEBUG_PRINTF("INFO: TX is not allowed for this modulation (%x)\n", pkt_data->modulation);
            return LGW_LBT_SUCCESS;
        }

        /* Get current FPGA time */
        lgw_fpga_reg_r(LGW_FPGA_TIMESTAMP, &val);
        fpga_time = (uint32_t)val;
        /* Get SX1301 time at last PPS */
        lgw_get_trigcnt(&sx1301_time);

        DEBUG_MSG("################################\n");
        switch(pkt_data->tx_mode) {
            case IMMEDIATE:
                DEBUG_MSG("tx_mode                    = IMMEDIATE\n");
                tx_start_time = (fpga_time + TX_START_DELAY) & LBT_TIMESTAMP_MASK; /* 0x007FFC00: to align on LBT time format (TIMESTAMP_CH) */
                break;
            case TIMESTAMPED:
                DEBUG_MSG("tx_mode                    = TIMESTAMPED\n");
                tx_start_time = pkt_data->count_us & LBT_TIMESTAMP_MASK;
                break;
            case ON_GPS:
                DEBUG_MSG("tx_mode                    = ON_GPS\n");
                tx_start_time = (sx1301_time + TX_START_DELAY + 1000000) & LBT_TIMESTAMP_MASK;
                break;
            default:
                return LGW_LBT_ERROR;
        }

        /* Select LBT Channel corresponding to required TX frequency */
        if (pkt_data->bandwidth == BW_125KHZ){
            tx_max_time = lbt_end_tx_delay_1ch_us;
            lbt_channel_decod_1 = -1;
            lbt_channel_decod_2 = -1;
            for (i=0; i<LBT_CHANNEL_FREQ_NB; i++) {
                if (is_equal_freq(pkt_data->freq_hz, lbt_channel_freq[i]) == true) {
                    DEBUG_PRINTF("LBT: select channel %d (%u Hz)\n", i, lbt_channel_freq[i]);
                    lbt_channel_decod_1 = i;
                    lbt_channel_decod_2 = i;
                    break;
                }
            }
        } else if (pkt_data->bandwidth == BW_250KHZ) {
            tx_max_time = lbt_end_tx_delay_2ch_us;

            /* In case of 250KHz, the TX freq has to be in between 2 channels of 200KHz BW. The TX can only be over 2 channels, not more */
            lbt_channel_decod_1 = -1;
            lbt_channel_decod_2 = -1;
            for (i=0; i<(LBT_CHANNEL_FREQ_NB-1); i++) {
                if (is_equal_freq(pkt_data->freq_hz, (lbt_channel_freq[i]+lbt_channel_freq[i+1])/2) == true) {
                    DEBUG_PRINTF("LBT: select channels %d,%d (%u Hz)\n", i, i+1, (lbt_channel_freq[i]+lbt_channel_freq[i+1])/2);
                    lbt_channel_decod_1 = i;
                    lbt_channel_decod_2 = i+1;
                    break;
                }
            }
        } else {
            lbt_channel_decod_1 = -1;
            lbt_channel_decod_2 = -1;
        }

        /* Get last time when selected channel was free */
        if ((lbt_channel_decod_1 >= 0) && (lbt_channel_decod_2 >= 0)) {
            lgw_fpga_reg_w(LGW_FPGA_LBT_TIMESTAMP_SELECT_CH, (int32_t)lbt_channel_decod_1);
            lgw_fpga_reg_r(LGW_FPGA_LBT_TIMESTAMP_CH, &val);
            lbt_time = lbt_time1 = (uint32_t)(val & 0x00FFFFFF) * 256; /* 24bits (1LSB = 256µs) */

            if (lbt_channel_decod_1 != lbt_channel_decod_2 ) {
                lgw_fpga_reg_w(LGW_FPGA_LBT_TIMESTAMP_SELECT_CH, (int32_t)lbt_channel_decod_2);
                lgw_fpga_reg_r(LGW_FPGA_LBT_TIMESTAMP_CH, &val);
                lbt_time2 = (uint32_t)(val & 0x00FFFFFF) * 256; /* 24bits (1LSB = 256µs) */

                if (lbt_time2 < lbt_time1) {
                    lbt_time = lbt_time2;
                }
            }
        } else {
            lbt_time = 0;
        }

        packet_duration = lgw_time_on_air(pkt_data, pkt_data->no_header) * 1000UL;
        tx_end_time = (tx_start_time + packet_duration) & LBT_TIMESTAMP_MASK;
        if (lbt_time < tx_end_time) {
            delta_time = tx_end_time - lbt_time;
        } else {
            /* It means LBT counter has wrapped */
            printf("LBT: lbt counter has wrapped\n");
            delta_time = (LBT_TIMESTAMP_MASK - lbt_time) + tx_end_time;
        }

        DEBUG_PRINTF("sx1301_time                = %u\n", sx1301_time & LBT_TIMESTAMP_MASK);
        DEBUG_PRINTF("fpga_time                  = %u\n", fpga_time & LBT_TIMESTAMP_MASK);
        DEBUG_PRINTF("tx_freq                    = %u\n", pkt_data->freq_hz);
        DEBUG_MSG("------------------------------------------------\n");
        DEBUG_PRINTF("packet_duration            = %u\n", packet_duration);
        DEBUG_PRINTF("tx_start_time              = %u\n", tx_start_time);
        DEBUG_PRINTF("lbt_time1                  = %u\n", lbt_time1);
        DEBUG_PRINTF("lbt_time2                  = %u\n", lbt_time2);
        DEBUG_PRINTF("lbt_time                   = %u\n", lbt_time);
        DEBUG_PRINTF("delta_time                 = %u\n", delta_time);
        DEBUG_MSG("------------------------------------------------\n");

        /* send data if allowed */
        /* lbt_time: last time when channel was free */
        /* tx_max_time: maximum time allowed to send packet since last free time */
        /* 2048: some margin */
        if (((delta_time < (tx_max_time - 2048)) && (lbt_time != 0)) || (lbt_enable == false)) {
            *tx_allowed = true;
        } else {
            DEBUG_MSG("ERROR: TX request rejected (LBT)\n");
            *tx_allowed = false;
        }
    } else {
        /* Always allow if LBT is disabled */
        *tx_allowed = true;
    }

    return LGW_LBT_SUCCESS;
}

/* --- EOF ------------------------------------------------------------------ */
