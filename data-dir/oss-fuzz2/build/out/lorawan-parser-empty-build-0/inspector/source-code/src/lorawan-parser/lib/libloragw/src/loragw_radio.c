/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    Functions used to handle LoRa concentrator radios.

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Michael Coracin
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */
#include <stdio.h>      /* printf fprintf */

#include "loragw_sx125x.h"
#include "loragw_sx1272_fsk.h"
#include "loragw_sx1272_lora.h"
#include "loragw_sx1276_fsk.h"
#include "loragw_sx1276_lora.h"
#include "loragw_spi.h"
#include "loragw_aux.h"
#include "loragw_reg.h"
#include "loragw_hal.h"
#include "loragw_radio.h"
#include "loragw_fpga.h"

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#if DEBUG_REG == 1
    #define DEBUG_MSG(str)              fprintf(stderr, str)
    #define DEBUG_PRINTF(fmt, args...)  fprintf(stderr,"%s:%d: "fmt, __FUNCTION__, __LINE__, args)
    #define CHECK_NULL(a)               if(a==NULL){fprintf(stderr,"%s:%d: ERROR: NULL POINTER AS ARGUMENT\n", __FUNCTION__, __LINE__);return LGW_REG_ERROR;}
#else
    #define DEBUG_MSG(str)
    #define DEBUG_PRINTF(fmt, args...)
    #define CHECK_NULL(a)               if(a==NULL){return LGW_REG_ERROR;}
#endif

/* -------------------------------------------------------------------------- */
/* --- PRIVATE TYPES -------------------------------------------------------- */

/**
@struct lgw_radio_type_version_s
@brief Associate a radio type with its corresponding expected version value
        read in the radio version register.
*/
struct lgw_radio_type_version_s {
    enum lgw_radio_type_e type;
    uint8_t reg_version;
};

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#define PLL_LOCK_MAX_ATTEMPTS 5

/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES ---------------------------------------------------- */

extern void *lgw_spi_target; /*! generic pointer to the SPI device */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS ---------------------------------------------------- */

void sx125x_write(uint8_t channel, uint8_t addr, uint8_t data);

uint8_t sx125x_read(uint8_t channel, uint8_t addr);

int setup_sx1272_FSK(uint32_t frequency);

int setup_sx1272_LoRa(uint32_t frequency);

int setup_sx1276_FSK(uint32_t frequency);

int reset_sx127x(enum lgw_radio_type_e radio_type);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

void sx125x_write(uint8_t channel, uint8_t addr, uint8_t data) {
    int reg_add, reg_dat, reg_cs;

    /* checking input parameters */
    if (channel >= LGW_RF_CHAIN_NB) {
        DEBUG_MSG("ERROR: INVALID RF_CHAIN\n");
        return;
    }
    if (addr >= 0x7F) {
        DEBUG_MSG("ERROR: ADDRESS OUT OF RANGE\n");
        return;
    }

    /* selecting the target radio */
    switch (channel) {
        case 0:
            reg_add = LGW_SPI_RADIO_A__ADDR;
            reg_dat = LGW_SPI_RADIO_A__DATA;
            reg_cs  = LGW_SPI_RADIO_A__CS;
            break;

        case 1:
            reg_add = LGW_SPI_RADIO_B__ADDR;
            reg_dat = LGW_SPI_RADIO_B__DATA;
            reg_cs  = LGW_SPI_RADIO_B__CS;
            break;

        default:
            DEBUG_PRINTF("ERROR: UNEXPECTED VALUE %d IN SWITCH STATEMENT\n", channel);
            return;
    }

    /* SPI master data write procedure */
    lgw_reg_w(reg_cs, 0);
    lgw_reg_w(reg_add, 0x80 | addr); /* MSB at 1 for write operation */
    lgw_reg_w(reg_dat, data);
    lgw_reg_w(reg_cs, 1);
    lgw_reg_w(reg_cs, 0);

    return;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

uint8_t sx125x_read(uint8_t channel, uint8_t addr) {
    int reg_add, reg_dat, reg_cs, reg_rb;
    int32_t read_value;

    /* checking input parameters */
    if (channel >= LGW_RF_CHAIN_NB) {
        DEBUG_MSG("ERROR: INVALID RF_CHAIN\n");
        return 0;
    }
    if (addr >= 0x7F) {
        DEBUG_MSG("ERROR: ADDRESS OUT OF RANGE\n");
        return 0;
    }

    /* selecting the target radio */
    switch (channel) {
        case 0:
            reg_add = LGW_SPI_RADIO_A__ADDR;
            reg_dat = LGW_SPI_RADIO_A__DATA;
            reg_cs  = LGW_SPI_RADIO_A__CS;
            reg_rb  = LGW_SPI_RADIO_A__DATA_READBACK;
            break;

        case 1:
            reg_add = LGW_SPI_RADIO_B__ADDR;
            reg_dat = LGW_SPI_RADIO_B__DATA;
            reg_cs  = LGW_SPI_RADIO_B__CS;
            reg_rb  = LGW_SPI_RADIO_B__DATA_READBACK;
            break;

        default:
            DEBUG_PRINTF("ERROR: UNEXPECTED VALUE %d IN SWITCH STATEMENT\n", channel);
            return 0;
    }

    /* SPI master data read procedure */
    lgw_reg_w(reg_cs, 0);
    lgw_reg_w(reg_add, addr); /* MSB at 0 for read operation */
    lgw_reg_w(reg_dat, 0);
    lgw_reg_w(reg_cs, 1);
    lgw_reg_w(reg_cs, 0);
    lgw_reg_r(reg_rb, &read_value);

    return (uint8_t)read_value;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int setup_sx1272_FSK(uint32_t frequency) {
    uint64_t freq_reg;
    uint8_t ModulationShaping = 0;
    uint8_t PllHop = 1;
    uint8_t LnaGain = 1;
    uint8_t LnaBoost = 3;
    uint8_t AdcBwAuto = 0;
    uint8_t AdcBw = 7;
    uint8_t AdcLowPwr = 0;
    uint8_t AdcTrim = 6;
    uint8_t AdcTest = 0;
    uint8_t RxBwExp = 2;
    uint8_t RxBwMant = 1;
    uint8_t RssiSmoothing = 5;
    uint8_t RssiOffset = 3;
    uint8_t reg_val;
    int x;

    /* Set in FSK mode */
    x = lgw_sx127x_reg_w(SX1272_REG_OPMODE, 0);
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1272_REG_OPMODE, 0 | (ModulationShaping << 3)); /* Sleep mode, no FSK shaping */
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1272_REG_OPMODE, 1 | (ModulationShaping << 3)); /* Standby mode, no FSK shaping */
    wait_ms(100);

    /* Set RF carrier frequency */
    x |= lgw_sx127x_reg_w(SX1272_REG_PLLHOP, PllHop << 7);
    freq_reg = ((uint64_t)frequency << 19) / (uint64_t)32000000;
    x |= lgw_sx127x_reg_w(SX1272_REG_FRFMSB, (freq_reg >> 16) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1272_REG_FRFMID, (freq_reg >> 8) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1272_REG_FRFLSB, (freq_reg >> 0) & 0xFF);

    /* Config */
    x |= lgw_sx127x_reg_w(SX1272_REG_LNA, LnaBoost | (LnaGain << 5)); /* Improved sensitivity, highest gain */
    x |= lgw_sx127x_reg_w(0x68, AdcBw | (AdcBwAuto << 3));
    x |= lgw_sx127x_reg_w(0x69, AdcTest | (AdcTrim << 4) | (AdcLowPwr << 7));

    /* set BR and FDEV for 200 kHz bandwidth*/
    x |= lgw_sx127x_reg_w(SX1272_REG_BITRATEMSB, 125);
    x |= lgw_sx127x_reg_w(SX1272_REG_BITRATELSB, 0);
    x |= lgw_sx127x_reg_w(SX1272_REG_FDEVMSB, 2);
    x |= lgw_sx127x_reg_w(SX1272_REG_FDEVLSB, 225);

    /* Config continues... */
    x |= lgw_sx127x_reg_w(SX1272_REG_RXCONFIG, 0); /* Disable AGC */
    x |= lgw_sx127x_reg_w(SX1272_REG_RSSICONFIG, RssiSmoothing | (RssiOffset << 3)); /* Set RSSI smoothing to 64 samples, RSSI offset 3dB */
    x |= lgw_sx127x_reg_w(SX1272_REG_RXBW, RxBwExp | (RxBwMant << 3)); /* RX BW = 100kHz, Mant=20, Exp=2 */
    x |= lgw_sx127x_reg_w(SX1272_REG_RXDELAY, 2);
    x |= lgw_sx127x_reg_w(SX1272_REG_PLL, 0x10); /* PLL BW set to 75 KHz */
    x |= lgw_sx127x_reg_w(0x47, 1); /* optimize PLL start-up time */

    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to configure SX1272\n");
        return x;
    }

    /* set Rx continuous mode */
    x = lgw_sx127x_reg_w(SX1272_REG_OPMODE, 5 | (ModulationShaping << 3)); /* Receiver Mode, no FSK shaping */
    wait_ms(500);
    x |= lgw_sx127x_reg_r(SX1272_REG_IRQFLAGS1, &reg_val);
    /* Check if RxReady and ModeReady */
    if ((TAKE_N_BITS_FROM(reg_val, 6, 1) == 0) || (TAKE_N_BITS_FROM(reg_val, 7, 1) == 0) || (x != LGW_REG_SUCCESS)) {
        DEBUG_MSG("ERROR: SX1272 failed to enter RX continuous mode\n");
        return LGW_REG_ERROR;
    }
    wait_ms(500);

    DEBUG_MSG("INFO: Successfully configured SX1272 for FSK modulation\n");

    return LGW_REG_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int setup_sx1272_LoRa(uint32_t frequency) {
    uint64_t freq_reg;
    uint8_t LoRaMode = 1;
    uint8_t bw = 0;
    uint8_t LowZin = 1;
    uint8_t sf = 7;
    uint8_t AgcAuto = 1;
    uint8_t LnaGain = 1;
    uint8_t TrimRxCrFo = 0;
    uint8_t LnaBoost = 3;
    uint8_t AdcBwAuto = 0;
    uint8_t AdcBw = 7;
    uint8_t AdcLowPwr = 0;
    uint8_t AdcTrim = 6;
    uint8_t AdcTest = 0;
    uint8_t reg_val;
    int x;

    /* Set in LoRa mode */
    x = lgw_sx127x_reg_w(SX1272_REG_LR_OPMODE, 0);
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_OPMODE, 0 | (LoRaMode << 7)); /* Sleep mode, LoRa Mode */
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_OPMODE, 1 | (LoRaMode << 7)); /* Standby mode, LoRa Mode */
    wait_ms(100);

    /* Set RF carrier frequency */
    freq_reg = ((uint64_t)frequency << 19) / (uint64_t)32000000;
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_FRFMSB, (freq_reg >> 16) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_FRFMID, (freq_reg >>  8) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_FRFLSB,  freq_reg        & 0xFF);

    /* Config */
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_MODEMCONFIG1, bw << 6); /* 125 KHz */
    x |= lgw_sx127x_reg_w(0x50, LowZin);
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_MODEMCONFIG2, (sf << 4) | (AgcAuto << 2));
    x |= lgw_sx127x_reg_w(SX1272_REG_LR_LNA, LnaBoost | (TrimRxCrFo << 3) | (LnaGain << 5));
    x |= lgw_sx127x_reg_w(0x68, AdcBw | (AdcBwAuto << 3));
    x |= lgw_sx127x_reg_w(0x69, AdcTest | (AdcTrim << 4) | (AdcLowPwr << 7));

    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to configure SX1272\n");
        return x;
    }

    /* Set in Rx continuous mode */
    x = lgw_sx127x_reg_w(SX1272_REG_LR_OPMODE, 5 | (LoRaMode << 7)); /* Receiver mode, LoRa Mode */
    wait_ms(100);
    x |= lgw_sx127x_reg_r(SX1272_REG_LR_OPMODE, &reg_val);
    if ((reg_val != (5 | (LoRaMode << 7))) || (x != LGW_REG_SUCCESS)) {
        DEBUG_MSG("ERROR: SX1272 failed to enter RX continuous mode\n");
        return x;
    }

    DEBUG_MSG("INFO: Successfully configured SX1272 for LoRa modulation\n");

    return LGW_REG_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int setup_sx1276_FSK(uint32_t frequency) {
    uint64_t freq_reg;
    uint8_t ModulationShaping = 0;
    uint8_t PllHop = 1;
    uint8_t LnaGain = 1;
    uint8_t LnaBoost = 3;
    uint8_t AdcBwAuto = 0;
    uint8_t AdcBw = 7;
    uint8_t AdcLowPwr = 0;
    uint8_t AdcTrim = 6;
    uint8_t AdcTest = 0;
    uint8_t RxBwExp = 2;
    uint8_t RxBwMant = 1;
    uint8_t RssiSmoothing = 5;
    uint8_t RssiOffset = 3;
    uint8_t reg_val;
    int x;

    /* Set in FSK mode */
    x = lgw_sx127x_reg_w(SX1276_REG_OPMODE, 0);
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1276_REG_OPMODE, 0 | (ModulationShaping << 3)); /* Sleep mode, no FSK shaping */
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1276_REG_OPMODE, 1 | (ModulationShaping << 3)); /* Standby mode, no FSK shaping */
    wait_ms(100);

    /* Set RF carrier frequency */
    x |= lgw_sx127x_reg_w(SX1276_REG_PLLHOP, PllHop << 7);
    freq_reg = ((uint64_t)frequency << 19) / (uint64_t)32000000;
    x |= lgw_sx127x_reg_w(SX1276_REG_FRFMSB, (freq_reg >> 16) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1276_REG_FRFMID, (freq_reg >> 8) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1276_REG_FRFLSB, (freq_reg >> 0) & 0xFF);

    /* Config */
    x |= lgw_sx127x_reg_w(SX1276_REG_LNA, LnaBoost | (LnaGain << 5)); /* Improved sensitivity, highest gain */
    x |= lgw_sx127x_reg_w(0x57, AdcBw | (AdcBwAuto << 3));
    x |= lgw_sx127x_reg_w(0x58, AdcTest | (AdcTrim << 4) | (AdcLowPwr << 7));

    /* set BR and FDEV for 200 kHz bandwidth*/
    x |= lgw_sx127x_reg_w(SX1276_REG_BITRATEMSB, 125);
    x |= lgw_sx127x_reg_w(SX1276_REG_BITRATELSB, 0);
    x |= lgw_sx127x_reg_w(SX1276_REG_FDEVMSB, 2);
    x |= lgw_sx127x_reg_w(SX1276_REG_FDEVLSB, 225);

    /* Config continues... */
    x |= lgw_sx127x_reg_w(SX1276_REG_RXCONFIG, 0); /* Disable AGC */
    x |= lgw_sx127x_reg_w(SX1276_REG_RSSICONFIG, RssiSmoothing | (RssiOffset << 3)); /* Set RSSI smoothing to 64 samples, RSSI offset 3dB */
    x |= lgw_sx127x_reg_w(SX1276_REG_RXBW, RxBwExp | (RxBwMant << 3)); /* RX BW = 100kHz, Mant=20, Exp=2 */
    x |= lgw_sx127x_reg_w(SX1276_REG_RXDELAY, 2);
    x |= lgw_sx127x_reg_w(SX1276_REG_PLL, 0x10); /* PLL BW set to 75 KHz */
    x |= lgw_sx127x_reg_w(0x43, 1); /* optimize PLL start-up time */

    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to configure SX1276\n");
        return x;
    }

    /* set Rx continuous mode */
    x = lgw_sx127x_reg_w(SX1276_REG_OPMODE, 5 | (ModulationShaping << 3)); /* Receiver Mode, no FSK shaping */
    wait_ms(500);
    x |= lgw_sx127x_reg_r(SX1276_REG_IRQFLAGS1, &reg_val);
    /* Check if RxReady and ModeReady */
    if ((TAKE_N_BITS_FROM(reg_val, 6, 1) == 0) || (TAKE_N_BITS_FROM(reg_val, 7, 1) == 0) || (x != LGW_REG_SUCCESS)) {
        DEBUG_MSG("ERROR: SX1276 failed to enter RX continuous mode\n");
        return LGW_REG_ERROR;
    }
    wait_ms(500);

    DEBUG_MSG("INFO: Successfully configured SX1276 for FSK modulation\n");

    return LGW_REG_SUCCESS;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int setup_sx1276_LoRa(uint32_t frequency) {
    uint64_t freq_reg;
    uint8_t LoRaMode = 1;
    uint8_t bw = 7;
    uint8_t codingRate = 1;
    uint8_t LowZin = 1;
    uint8_t sf = 7;
    uint8_t AgcAuto = 1;
    uint8_t LnaGain = 1;
    uint8_t LnaBoost = 3;
    uint8_t AdcBwAuto = 0;
    uint8_t AdcBw = 7;
    uint8_t AdcLowPwr = 0;
    uint8_t AdcTrim = 6;
    uint8_t AdcTest = 0;
    uint8_t reg_val;
    int x;

    /* Set in LoRa mode */
    x = lgw_sx127x_reg_w(SX1276_REG_LR_OPMODE, 0);
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_OPMODE, 0 | (LoRaMode << 7)); /* Sleep mode, LoRa Mode */
    wait_ms(100);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_OPMODE, 1 | (LoRaMode << 7)); /* Standby mode, LoRa Mode */
    wait_ms(100);

    /* Set RF carrier frequency */
    freq_reg = ((uint64_t)frequency << 19) / (uint64_t)32000000;
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_FRFMSB, (freq_reg >> 16) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_FRFMID, (freq_reg >>  8) & 0xFF);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_FRFLSB,  freq_reg        & 0xFF);

    /* Config */
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_MODEMCONFIG1, 0 | (codingRate << 1) | (bw << 4)); /* 125 KHz, 4/5 */
    x |= lgw_sx127x_reg_w(0x69, LowZin);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_MODEMCONFIG2, sf << 4);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_MODEMCONFIG3, AgcAuto << 2);
    x |= lgw_sx127x_reg_w(SX1276_REG_LR_LNA, LnaBoost | (LnaGain << 5));
    x |= lgw_sx127x_reg_w(0x57, AdcBw | (AdcBwAuto << 3));
    x |= lgw_sx127x_reg_w(0x57, AdcTest | (AdcTrim << 4) | (AdcLowPwr << 7));

    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: Failed to configure SX1276\n");
        return x;
    }

    /* Set in Rx continuous mode */
    x = lgw_sx127x_reg_w(SX1276_REG_LR_OPMODE, 5 | (LoRaMode << 7)); /* Receiver mode, LoRa Mode */
    wait_ms(100);
    x |= lgw_sx127x_reg_r(SX1276_REG_LR_OPMODE, &reg_val);
    if ((reg_val != (5 | (LoRaMode << 7))) || (x != LGW_REG_SUCCESS)) {
        DEBUG_MSG("ERROR: SX1276 failed to enter RX continuous mode\n");
        return x;
    }

    DEBUG_MSG("INFO: Successfully configured SX1276 for LoRa modulation\n");

    return LGW_REG_SUCCESS;
}

int reset_sx127x(enum lgw_radio_type_e radio_type) {
    int x;

    switch(radio_type) {
        case LGW_RADIO_TYPE_SX1276:
            x  = lgw_fpga_reg_w(LGW_FPGA_CTRL_RADIO_RESET, 0);
            x |= lgw_fpga_reg_w(LGW_FPGA_CTRL_RADIO_RESET, 1);
            if (x != LGW_SPI_SUCCESS) {
                DEBUG_MSG("ERROR: Failed to reset sx127x\n");
                return x;
            }
            break;
        case LGW_RADIO_TYPE_SX1272:
            x  = lgw_fpga_reg_w(LGW_FPGA_CTRL_RADIO_RESET, 1);
            x |= lgw_fpga_reg_w(LGW_FPGA_CTRL_RADIO_RESET, 0);
            if (x != LGW_SPI_SUCCESS) {
                DEBUG_MSG("ERROR: Failed to reset sx127x\n");
                return x;
            }
            break;
        default:
            DEBUG_PRINTF("ERROR: Failed to reset sx127x, not supported (%d)\n", radio_type);
            return LGW_REG_ERROR;
    }

    return LGW_REG_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS DEFINITION ------------------------------------------ */

int setup_sx125x(uint8_t rf_chain, uint8_t rf_clkout, bool rf_enable, uint8_t rf_radio_type, uint32_t freq_hz) {
    uint32_t part_int = 0;
    uint32_t part_frac = 0;
    int cpt_attempts = 0;

    if (rf_chain >= LGW_RF_CHAIN_NB) {
        DEBUG_MSG("ERROR: INVALID RF_CHAIN\n");
        return -1;
    }

    /* Get version to identify SX1255/57 silicon revision */
    DEBUG_PRINTF("Note: SX125x #%d version register returned 0x%02x\n", rf_chain, sx125x_read(rf_chain, 0x07));

    /* General radio setup */
    if (rf_clkout == rf_chain) {
        sx125x_write(rf_chain, 0x10, SX125x_TX_DAC_CLK_SEL + 2);
        DEBUG_PRINTF("Note: SX125x #%d clock output enabled\n", rf_chain);
    } else {
        sx125x_write(rf_chain, 0x10, SX125x_TX_DAC_CLK_SEL);
        DEBUG_PRINTF("Note: SX125x #%d clock output disabled\n", rf_chain);
    }

    switch (rf_radio_type) {
        case LGW_RADIO_TYPE_SX1255:
            sx125x_write(rf_chain, 0x28, SX125x_XOSC_GM_STARTUP + SX125x_XOSC_DISABLE*16);
            break;
        case LGW_RADIO_TYPE_SX1257:
            sx125x_write(rf_chain, 0x26, SX125x_XOSC_GM_STARTUP + SX125x_XOSC_DISABLE*16);
            break;
        default:
            DEBUG_PRINTF("ERROR: UNEXPECTED VALUE %d FOR RADIO TYPE\n", rf_radio_type);
            break;
    }

    if (rf_enable == true) {
        /* Tx gain and trim */
        sx125x_write(rf_chain, 0x08, SX125x_TX_MIX_GAIN + SX125x_TX_DAC_GAIN*16);
        sx125x_write(rf_chain, 0x0A, SX125x_TX_ANA_BW + SX125x_TX_PLL_BW*32);
        sx125x_write(rf_chain, 0x0B, SX125x_TX_DAC_BW);

        /* Rx gain and trim */
        sx125x_write(rf_chain, 0x0C, SX125x_LNA_ZIN + SX125x_RX_BB_GAIN*2 + SX125x_RX_LNA_GAIN*32);
        sx125x_write(rf_chain, 0x0D, SX125x_RX_BB_BW + SX125x_RX_ADC_TRIM*4 + SX125x_RX_ADC_BW*32);
        sx125x_write(rf_chain, 0x0E, SX125x_ADC_TEMP + SX125x_RX_PLL_BW*2);

        /* set RX PLL frequency */
        switch (rf_radio_type) {
            case LGW_RADIO_TYPE_SX1255:
                part_int = freq_hz / (SX125x_32MHz_FRAC << 7); /* integer part, gives the MSB */
                part_frac = ((freq_hz % (SX125x_32MHz_FRAC << 7)) << 9) / SX125x_32MHz_FRAC; /* fractional part, gives middle part and LSB */
                break;
            case LGW_RADIO_TYPE_SX1257:
                part_int = freq_hz / (SX125x_32MHz_FRAC << 8); /* integer part, gives the MSB */
                part_frac = ((freq_hz % (SX125x_32MHz_FRAC << 8)) << 8) / SX125x_32MHz_FRAC; /* fractional part, gives middle part and LSB */
                break;
            default:
                DEBUG_PRINTF("ERROR: UNEXPECTED VALUE %d FOR RADIO TYPE\n", rf_radio_type);
                break;
        }

        sx125x_write(rf_chain, 0x01,0xFF & part_int); /* Most Significant Byte */
        sx125x_write(rf_chain, 0x02,0xFF & (part_frac >> 8)); /* middle byte */
        sx125x_write(rf_chain, 0x03,0xFF & part_frac); /* Least Significant Byte */

        /* start and PLL lock */
        do {
            if (cpt_attempts >= PLL_LOCK_MAX_ATTEMPTS) {
                DEBUG_MSG("ERROR: FAIL TO LOCK PLL\n");
                return -1;
            }
            sx125x_write(rf_chain, 0x00, 1); /* enable Xtal oscillator */
            sx125x_write(rf_chain, 0x00, 3); /* Enable RX (PLL+FE) */
            ++cpt_attempts;
            DEBUG_PRINTF("Note: SX125x #%d PLL start (attempt %d)\n", rf_chain, cpt_attempts);
            wait_ms(1);
        } while((sx125x_read(rf_chain, 0x11) & 0x02) == 0);
    } else {
        DEBUG_PRINTF("Note: SX125x #%d kept in standby mode\n", rf_chain);
    }

    return 0;
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_sx127x_reg_w(uint8_t address, uint8_t reg_value) {
    return lgw_spi_w(lgw_spi_target, LGW_SPI_MUX_MODE1, LGW_SPI_MUX_TARGET_SX127X, address, reg_value);
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_sx127x_reg_r(uint8_t address, uint8_t *reg_value) {
    return lgw_spi_r(lgw_spi_target, LGW_SPI_MUX_MODE1, LGW_SPI_MUX_TARGET_SX127X, address, reg_value);
}

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int lgw_setup_sx127x(uint32_t frequency, uint8_t modulation) {
    int x, i;
    uint8_t version;
    enum lgw_radio_type_e radio_type = LGW_RADIO_TYPE_NONE;
    struct lgw_radio_type_version_s supported_radio_type[2] = {
        {LGW_RADIO_TYPE_SX1272, 0x22},
        {LGW_RADIO_TYPE_SX1276, 0x12}
    };

    /* Check parameters */
    if ((modulation != MOD_FSK) && (modulation != MOD_LORA)) {
        DEBUG_PRINTF("ERROR: modulation not supported for SX127x (%u)\n", modulation);
        return LGW_REG_ERROR;
    }

    /* Probing radio type */
    for (i = 0; i < (int)(sizeof supported_radio_type); i++) {
        /* Reset the radio */
        x = reset_sx127x(supported_radio_type[i].type);
        if (x != LGW_SPI_SUCCESS) {
            DEBUG_MSG("ERROR: Failed to reset sx127x\n");
            return x;
        }
        /* Read version register */
        x = lgw_sx127x_reg_r(0x42, &version);
        if (x != LGW_SPI_SUCCESS) {
            DEBUG_MSG("ERROR: Failed to read sx127x version register\n");
            return x;
        }
        /* Check if we got the expected version */
        if (version != supported_radio_type[i].reg_version) {
            DEBUG_PRINTF("INFO: sx127x version register - read:0x%02x, expected:0x%02x\n", version, supported_radio_type[i].reg_version);
            continue;
        } else {
            DEBUG_PRINTF("INFO: sx127x radio has been found (type:%d, version:0x%02x)\n", supported_radio_type[i].type, version);
            radio_type = supported_radio_type[i].type;
            break;
        }
    }
    if (radio_type == LGW_RADIO_TYPE_NONE) {
        DEBUG_MSG("ERROR: sx127x radio has not been found\n");
        return LGW_REG_ERROR;
    }

    /* Setup the radio */
    switch (modulation) {
        case MOD_LORA:
            if (radio_type == LGW_RADIO_TYPE_SX1272) {
                x = setup_sx1272_LoRa(frequency);
            } else {
                x = setup_sx1276_LoRa(frequency);
            }
            break;
        case MOD_FSK:
            if (radio_type == LGW_RADIO_TYPE_SX1272) {
                x = setup_sx1272_FSK(frequency);
            } else {
                x = setup_sx1276_FSK(frequency);
            }
            break;
        default:
            /* Should not happen */
            break;
    }
    if (x != LGW_REG_SUCCESS) {
        DEBUG_MSG("ERROR: failed to setup SX127x\n");
        return x;
    }

    return LGW_REG_SUCCESS;
}

/* --- EOF ------------------------------------------------------------------ */
