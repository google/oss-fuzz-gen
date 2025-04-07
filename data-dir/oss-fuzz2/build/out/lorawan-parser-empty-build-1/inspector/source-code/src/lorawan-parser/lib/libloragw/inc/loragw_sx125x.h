/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
    (C)2013 Semtech

Description: SX125x radio registers and constant definitions

License: Revised BSD License, see LICENSE.TXT file include in the project

Maintainer: Michael Coracin
*/
#ifndef __SX125X_REGS_H__
#define __SX125X_REGS_H__

/*
SX1257 frequency setting :
F_register(24bit) = F_rf (Hz) / F_step(Hz)
                  = F_rf (Hz) * 2^19 / F_xtal(Hz)
                  = F_rf (Hz) * 2^19 / 32e6
                  = F_rf (Hz) * 256/15625

SX1255 frequency setting :
F_register(24bit) = F_rf (Hz) / F_step(Hz)
                  = F_rf (Hz) * 2^20 / F_xtal(Hz)
                  = F_rf (Hz) * 2^20 / 32e6
                  = F_rf (Hz) * 512/15625
*/

#define SX125x_TX_DAC_CLK_SEL   1   /* 0:int, 1:ext */
#define SX125x_TX_DAC_GAIN      2   /* 3:0, 2:-3, 1:-6, 0:-9 dBFS (default 2) */
#define SX125x_TX_MIX_GAIN      14  /* -38 + 2*TxMixGain dB (default 14) */
#define SX125x_TX_PLL_BW        1   /* 0:75, 1:150, 2:225, 3:300 kHz (default 3) */
#define SX125x_TX_ANA_BW        0   /* 17.5 / 2*(41-TxAnaBw) MHz (default 0) */
#define SX125x_TX_DAC_BW        5   /* 24 + 8*TxDacBw Nb FIR taps (default 2) */
#define SX125x_RX_LNA_GAIN      1   /* 1 to 6, 1 highest gain */
#define SX125x_RX_BB_GAIN       12  /* 0 to 15 , 15 highest gain */
#define SX125x_LNA_ZIN          1   /* 0:50, 1:200 Ohms (default 1) */
#define SX125x_RX_ADC_BW        7   /* 0 to 7, 2:100<BW<200, 5:200<BW<400,7:400<BW kHz SSB (default 7) */
#define SX125x_RX_ADC_TRIM      6   /* 0 to 7, 6 for 32MHz ref, 5 for 36MHz ref */
#define SX125x_RX_BB_BW         0   /* 0:750, 1:500, 2:375; 3:250 kHz SSB (default 1, max 3) */
#define SX125x_RX_PLL_BW        0   /* 0:75, 1:150, 2:225, 3:300 kHz (default 3, max 3) */
#define SX125x_ADC_TEMP         0   /* ADC temperature measurement mode (default 0) */
#define SX125x_XOSC_GM_STARTUP  13  /* (default 13) */
#define SX125x_XOSC_DISABLE     2   /* Disable of Xtal Oscillator blocks bit0:regulator, bit1:core(gm), bit2:amplifier */

#endif // __SX125X_REGS_H__
