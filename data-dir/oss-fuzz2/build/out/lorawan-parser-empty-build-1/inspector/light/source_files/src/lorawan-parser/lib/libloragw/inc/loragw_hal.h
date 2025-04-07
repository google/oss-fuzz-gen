/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    LoRa concentrator Hardware Abstraction Layer

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Sylvain Miermont
*/


#ifndef _LORAGW_HAL_H
#define _LORAGW_HAL_H

/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */

#include "config.h"     /* library configuration options (dynamically generated) */

/* -------------------------------------------------------------------------- */
/* --- PUBLIC MACROS -------------------------------------------------------- */

#define IS_LORA_BW(bw)          ((bw == BW_125KHZ) || (bw == BW_250KHZ) || (bw == BW_500KHZ))
#define IS_LORA_STD_DR(dr)      ((dr == DR_LORA_SF7) || (dr == DR_LORA_SF8) || (dr == DR_LORA_SF9) || (dr == DR_LORA_SF10) || (dr == DR_LORA_SF11) || (dr == DR_LORA_SF12))
#define IS_LORA_MULTI_DR(dr)    ((dr & ~DR_LORA_MULTI) == 0) /* ones outside of DR_LORA_MULTI bitmask -> not a combination of LoRa datarates */
#define IS_LORA_CR(cr)          ((cr == CR_LORA_4_5) || (cr == CR_LORA_4_6) || (cr == CR_LORA_4_7) || (cr == CR_LORA_4_8))

#define IS_FSK_BW(bw)           ((bw >= 1) && (bw <= 7))
#define IS_FSK_DR(dr)           ((dr >= DR_FSK_MIN) && (dr <= DR_FSK_MAX))

#define IS_TX_MODE(mode)        ((mode == IMMEDIATE) || (mode == TIMESTAMPED) || (mode == ON_GPS))

/* -------------------------------------------------------------------------- */
/* --- PUBLIC CONSTANTS ----------------------------------------------------- */

/* return status code */
#define LGW_HAL_SUCCESS     0
#define LGW_HAL_ERROR       -1
#define LGW_LBT_ISSUE       1

/* radio-specific parameters */
#define LGW_XTAL_FREQU      32000000            /* frequency of the RF reference oscillator */
#define LGW_RF_CHAIN_NB     2                   /* number of RF chains */
#define LGW_RF_RX_BANDWIDTH {1000000, 1000000}  /* bandwidth of the radios */

/* type of if_chain + modem */
#define IF_UNDEFINED        0
#define IF_LORA_STD         0x10    /* if + standard single-SF LoRa modem */
#define IF_LORA_MULTI       0x11    /* if + LoRa receiver with multi-SF capability */
#define IF_FSK_STD          0x20    /* if + standard FSK modem */

/* concentrator chipset-specific parameters */
/* to use array parameters, declare a local const and use 'if_chain' as index */
#define LGW_IF_CHAIN_NB     10    /* number of IF+modem RX chains */
#define LGW_PKT_FIFO_SIZE   8    /* depth of the RX packet FIFO */
#define LGW_DATABUFF_SIZE   1024    /* size in bytes of the RX data buffer (contains payload & metadata) */
#define LGW_REF_BW          125000    /* typical bandwidth of data channel */
#define LGW_MULTI_NB        8    /* number of LoRa 'multi SF' chains */
#define LGW_IFMODEM_CONFIG {\
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_MULTI, \
        IF_LORA_STD, \
        IF_FSK_STD } /* configuration of available IF chains and modems on the hardware */

/* values available for the 'modulation' parameters */
/* NOTE: arbitrary values */
#define MOD_UNDEFINED   0
#define MOD_LORA        0x10
#define MOD_FSK         0x20

/* values available for the 'bandwidth' parameters (LoRa & FSK) */
/* NOTE: directly encode FSK RX bandwidth, do not change */
#define BW_UNDEFINED    0
#define BW_500KHZ       0x01
#define BW_250KHZ       0x02
#define BW_125KHZ       0x03
#define BW_62K5HZ       0x04
#define BW_31K2HZ       0x05
#define BW_15K6HZ       0x06
#define BW_7K8HZ        0x07

/* values available for the 'datarate' parameters */
/* NOTE: LoRa values used directly to code SF bitmask in 'multi' modem, do not change */
#define DR_UNDEFINED    0
#define DR_LORA_SF7     0x02
#define DR_LORA_SF8     0x04
#define DR_LORA_SF9     0x08
#define DR_LORA_SF10    0x10
#define DR_LORA_SF11    0x20
#define DR_LORA_SF12    0x40
#define DR_LORA_MULTI   0x7E
/* NOTE: for FSK directly use baudrate between 500 bauds and 250 kbauds */
#define DR_FSK_MIN      500
#define DR_FSK_MAX      250000

/* values available for the 'coderate' parameters (LoRa only) */
/* NOTE: arbitrary values */
#define CR_UNDEFINED    0
#define CR_LORA_4_5     0x01
#define CR_LORA_4_6     0x02
#define CR_LORA_4_7     0x03
#define CR_LORA_4_8     0x04

/* values available for the 'status' parameter */
/* NOTE: values according to hardware specification */
#define STAT_UNDEFINED  0x00
#define STAT_NO_CRC     0x01
#define STAT_CRC_BAD    0x11
#define STAT_CRC_OK     0x10

/* values available for the 'tx_mode' parameter */
#define IMMEDIATE       0
#define TIMESTAMPED     1
#define ON_GPS          2
//#define ON_EVENT      3
//#define GPS_DELAYED   4
//#define EVENT_DELAYED 5

/* values available for 'select' in the status function */
#define TX_STATUS       1
#define RX_STATUS       2

/* status code for TX_STATUS */
/* NOTE: arbitrary values */
#define TX_STATUS_UNKNOWN   0
#define TX_OFF              1    /* TX modem disabled, it will ignore commands */
#define TX_FREE             2    /* TX modem is free, ready to receive a command */
#define TX_SCHEDULED        3    /* TX modem is loaded, ready to send the packet after an event and/or delay */
#define TX_EMITTING         4    /* TX modem is emitting */

/* status code for RX_STATUS */
/* NOTE: arbitrary values */
#define RX_STATUS_UNKNOWN   0
#define RX_OFF              1    /* RX modem is disabled, it will ignore commands  */
#define RX_ON               2    /* RX modem is receiving */
#define RX_SUSPENDED        3    /* RX is suspended while a TX is ongoing */

/* Maximum size of Tx gain LUT */
#define TX_GAIN_LUT_SIZE_MAX 16

/* -------------------------------------------------------------------------- */
/* --- PUBLIC TYPES --------------------------------------------------------- */

/**
@enum lgw_radio_type_e
@brief Radio types that can be found on the LoRa Gateway
*/
enum lgw_radio_type_e {
    LGW_RADIO_TYPE_NONE,
    LGW_RADIO_TYPE_SX1255,
    LGW_RADIO_TYPE_SX1257,
    LGW_RADIO_TYPE_SX1272,
    LGW_RADIO_TYPE_SX1276
};

/**
@struct lgw_conf_board_s
@brief Configuration structure for board specificities
*/
struct lgw_conf_board_s {
    bool        lorawan_public; /*!> Enable ONLY for *public* networks using the LoRa MAC protocol */
    uint8_t     clksrc;         /*!> Index of RF chain which provides clock to concentrator */
};

/**
@struct lgw_conf_lbt_s
@brief Configuration structure for LBT specificities
*/
struct lgw_conf_lbt_s {
    bool        enable;             /*!> enable or disable LBT */
    uint8_t     rssi_target;        /*!> RSSI threshold to detect if channel is busy or not */
    uint8_t     nb_channel;         /*!> number of LBT channels */
    uint16_t    scan_time_us;       /*!> channel activity scan duration, in microseconds */
    uint32_t    start_freq;         /*!> first LBT channel frequency */
    uint32_t    tx_delay_1ch_us;    /*!> maximum time allowed to send a packet since channel was free, when TX is on one channel only */
    uint32_t    tx_delay_2ch_us;    /*!> maximum time allowed to send a packet since channel was free, when TX is on two channels */
};

/**
@struct lgw_conf_rxrf_s
@brief Configuration structure for a RF chain
*/
struct lgw_conf_rxrf_s {
    bool            enable;         /*!> enable or disable that RF chain */
    uint32_t        freq_hz;        /*!> center frequency of the radio in Hz */
    float            rssi_offset;   /*!> Board-specific RSSI correction factor */
    enum lgw_radio_type_e    type;  /*!> Radio type for that RF chain (SX1255, SX1257....) */
    bool            tx_enable;      /*!> enable or disable TX on that RF chain */
};

/**
@struct lgw_conf_rxif_s
@brief Configuration structure for an IF chain
*/
struct lgw_conf_rxif_s {
    bool        enable;         /*!> enable or disable that IF chain */
    uint8_t     rf_chain;       /*!> to which RF chain is that IF chain associated */
    int32_t     freq_hz;        /*!> center frequ of the IF chain, relative to RF chain frequency */
    uint8_t     bandwidth;      /*!> RX bandwidth, 0 for default */
    uint32_t    datarate;       /*!> RX datarate, 0 for default */
    uint8_t     sync_word_size; /*!> size of FSK sync word (number of bytes, 0 for default) */
    uint64_t    sync_word;      /*!> FSK sync word (ALIGN RIGHT, eg. 0xC194C1) */
};

/**
@struct lgw_pkt_rx_s
@brief Structure containing the metadata of a packet that was received and a pointer to the payload
*/
struct lgw_pkt_rx_s {
    uint32_t    freq_hz;        /*!> central frequency of the IF chain */
    uint8_t     if_chain;       /*!> by which IF chain was packet received */
    uint8_t     status;         /*!> status of the received packet */
    uint32_t    count_us;       /*!> internal concentrator counter for timestamping, 1 microsecond resolution */
    uint8_t     rf_chain;       /*!> through which RF chain the packet was received */
    uint8_t     modulation;     /*!> modulation used by the packet */
    uint8_t     bandwidth;      /*!> modulation bandwidth (LoRa only) */
    uint32_t    datarate;       /*!> RX datarate of the packet (SF for LoRa) */
    uint8_t     coderate;       /*!> error-correcting code of the packet (LoRa only) */
    float       rssi;           /*!> average packet RSSI in dB */
    float       snr;            /*!> average packet SNR, in dB (LoRa only) */
    float       snr_min;        /*!> minimum packet SNR, in dB (LoRa only) */
    float       snr_max;        /*!> maximum packet SNR, in dB (LoRa only) */
    uint16_t    crc;            /*!> CRC that was received in the payload */
    uint16_t    size;           /*!> payload size in bytes */
    uint8_t     payload[256];   /*!> buffer containing the payload */
};

/**
@struct lgw_pkt_tx_s
@brief Structure containing the configuration of a packet to send and a pointer to the payload
*/
struct lgw_pkt_tx_s {
    uint32_t    freq_hz;        /*!> center frequency of TX */
    uint8_t     tx_mode;        /*!> select on what event/time the TX is triggered */
    uint32_t    count_us;       /*!> timestamp or delay in microseconds for TX trigger */
    uint8_t     rf_chain;       /*!> through which RF chain will the packet be sent */
    int8_t      rf_power;       /*!> TX power, in dBm */
    uint8_t     modulation;     /*!> modulation to use for the packet */
    uint8_t     bandwidth;      /*!> modulation bandwidth (LoRa only) */
    uint32_t    datarate;       /*!> TX datarate (baudrate for FSK, SF for LoRa) */
    uint8_t     coderate;       /*!> error-correcting code of the packet (LoRa only) */
    bool        invert_pol;     /*!> invert signal polarity, for orthogonal downlinks (LoRa only) */
    uint8_t     f_dev;          /*!> frequency deviation, in kHz (FSK only) */
    uint16_t    preamble;       /*!> set the preamble length, 0 for default */
    bool        no_crc;         /*!> if true, do not send a CRC in the packet */
    bool        no_header;      /*!> if true, enable implicit header mode (LoRa), fixed length (FSK) */
    uint16_t    size;           /*!> payload size in bytes */
    uint8_t     payload[256];   /*!> buffer containing the payload */
};

/**
@struct lgw_tx_gain_s
@brief Structure containing all gains of Tx chain
*/
struct lgw_tx_gain_s {
    uint8_t dig_gain;   /*!> 2 bits, control of the digital gain of SX1301 */
    uint8_t pa_gain;    /*!> 2 bits, control of the external PA (SX1301 I/O) */
    uint8_t dac_gain;   /*!> 2 bits, control of the radio DAC */
    uint8_t mix_gain;   /*!> 4 bits, control of the radio mixer */
    int8_t  rf_power;   /*!> measured TX power at the board connector, in dBm */
};

/**
@struct lgw_tx_gain_lut_s
@brief Structure defining the Tx gain LUT
*/
struct lgw_tx_gain_lut_s {
    struct lgw_tx_gain_s    lut[TX_GAIN_LUT_SIZE_MAX];  /*!> Array of Tx gain struct */
    uint8_t                 size;                       /*!> Number of LUT indexes */
};

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS PROTOTYPES ------------------------------------------ */

/**
@brief Configure the gateway board
@param conf structure containing the configuration parameters
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_board_setconf(struct lgw_conf_board_s conf);

/**
@brief Configure the gateway lbt function
@param conf structure containing the configuration parameters
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_lbt_setconf(struct lgw_conf_lbt_s conf);

/**
@brief Configure an RF chain (must configure before start)
@param rf_chain number of the RF chain to configure [0, LGW_RF_CHAIN_NB - 1]
@param conf structure containing the configuration parameters
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_rxrf_setconf(uint8_t rf_chain, struct lgw_conf_rxrf_s conf);

/**
@brief Configure an IF chain + modem (must configure before start)
@param if_chain number of the IF chain + modem to configure [0, LGW_IF_CHAIN_NB - 1]
@param conf structure containing the configuration parameters
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_rxif_setconf(uint8_t if_chain, struct lgw_conf_rxif_s conf);

/**
@brief Configure the Tx gain LUT
@param pointer to structure defining the LUT
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_txgain_setconf(struct lgw_tx_gain_lut_s *conf);

/**
@brief Connect to the LoRa concentrator, reset it and configure it according to previously set parameters
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_start(void);

/**
@brief Stop the LoRa concentrator and disconnect it
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_stop(void);

/**
@brief A non-blocking function that will fetch up to 'max_pkt' packets from the LoRa concentrator FIFO and data buffer
@param max_pkt maximum number of packet that must be retrieved (equal to the size of the array of struct)
@param pkt_data pointer to an array of struct that will receive the packet metadata and payload pointers
@return LGW_HAL_ERROR id the operation failed, else the number of packets retrieved
*/
int lgw_receive(uint8_t max_pkt, struct lgw_pkt_rx_s *pkt_data);

/**
@brief Schedule a packet to be send immediately or after a delay depending on tx_mode
@param pkt_data structure containing the data and metadata for the packet to send
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else

/!\ When sending a packet, there is a 1.5 ms delay for the analog circuitry to start and be stable (TX_START_DELAY).
In 'timestamp' mode, this is transparent: the modem is started 1.5ms before the user-set timestamp value is reached, the preamble of the packet start right when the internal timestamp counter reach target value.
In 'immediate' mode, the packet is emitted as soon as possible: transferring the packet (and its parameters) from the host to the concentrator takes some time, then there is the TX_START_DELAY, then the packet is emitted.
In 'triggered' mode (aka PPS/GPS mode), the packet, typically a beacon, is emitted 1.5ms after a rising edge of the trigger signal. Because there is no way to anticipate the triggering event and start the analog circuitry beforehand, that delay must be taken into account in the protocol.
*/
int lgw_send(struct lgw_pkt_tx_s pkt_data);

/**
@brief Give the the status of different part of the LoRa concentrator
@param select is used to select what status we want to know
@param code is used to return the status code
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_status(uint8_t select, uint8_t *code);

/**
@brief Abort a currently scheduled or ongoing TX
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_abort_tx(void);

/**
@brief Return value of internal counter when latest event (eg GPS pulse) was captured
@param trig_cnt_us pointer to receive timestamp value
@return LGW_HAL_ERROR id the operation failed, LGW_HAL_SUCCESS else
*/
int lgw_get_trigcnt(uint32_t* trig_cnt_us);

/**
@brief Allow user to check the version/options of the library once compiled
@return pointer on a human-readable null terminated string
*/
const char* lgw_version_info(void);

/**
@brief Return time on air of given packet, in milliseconds
@param packet is a pointer to the packet structure
@param isBeacon indicates if the packet is a beacon or not
@return the packet time on air in milliseconds
*/
uint32_t lgw_time_on_air(struct lgw_pkt_tx_s *packet, bool isBeacon);

#endif

/* --- EOF ------------------------------------------------------------------ */
