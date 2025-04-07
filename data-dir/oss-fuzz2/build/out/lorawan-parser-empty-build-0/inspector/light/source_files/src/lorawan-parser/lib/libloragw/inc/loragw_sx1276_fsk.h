/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
    (C)2013 Semtech

Description: SX1276 FSK modem registers

License: Revised BSD License, see LICENSE.TXT file include in the project

Maintainer: Michael Coracin
*/
#ifndef _LORAGW_SX1276_REGS_FSK_H
#define _LORAGW_SX1276_REGS_FSK_H

/*!
 * ============================================================================
 * SX1276 Internal registers Address
 * ============================================================================
 */
#define SX1276_REG_FIFO                                    0x00
// Common settings
#define SX1276_REG_OPMODE                                  0x01
#define SX1276_REG_BITRATEMSB                              0x02
#define SX1276_REG_BITRATELSB                              0x03
#define SX1276_REG_FDEVMSB                                 0x04
#define SX1276_REG_FDEVLSB                                 0x05
#define SX1276_REG_FRFMSB                                  0x06
#define SX1276_REG_FRFMID                                  0x07
#define SX1276_REG_FRFLSB                                  0x08
// Tx settings
#define SX1276_REG_PACONFIG                                0x09
#define SX1276_REG_PARAMP                                  0x0A
#define SX1276_REG_OCP                                     0x0B
// Rx settings
#define SX1276_REG_LNA                                     0x0C
#define SX1276_REG_RXCONFIG                                0x0D
#define SX1276_REG_RSSICONFIG                              0x0E
#define SX1276_REG_RSSICOLLISION                           0x0F
#define SX1276_REG_RSSITHRESH                              0x10
#define SX1276_REG_RSSIVALUE                               0x11
#define SX1276_REG_RXBW                                    0x12
#define SX1276_REG_AFCBW                                   0x13
#define SX1276_REG_OOKPEAK                                 0x14
#define SX1276_REG_OOKFIX                                  0x15
#define SX1276_REG_OOKAVG                                  0x16
#define SX1276_REG_RES17                                   0x17
#define SX1276_REG_RES18                                   0x18
#define SX1276_REG_RES19                                   0x19
#define SX1276_REG_AFCFEI                                  0x1A
#define SX1276_REG_AFCMSB                                  0x1B
#define SX1276_REG_AFCLSB                                  0x1C
#define SX1276_REG_FEIMSB                                  0x1D
#define SX1276_REG_FEILSB                                  0x1E
#define SX1276_REG_PREAMBLEDETECT                          0x1F
#define SX1276_REG_RXTIMEOUT1                              0x20
#define SX1276_REG_RXTIMEOUT2                              0x21
#define SX1276_REG_RXTIMEOUT3                              0x22
#define SX1276_REG_RXDELAY                                 0x23
// Oscillator settings
#define SX1276_REG_OSC                                     0x24
// Packet handler settings
#define SX1276_REG_PREAMBLEMSB                             0x25
#define SX1276_REG_PREAMBLELSB                             0x26
#define SX1276_REG_SYNCCONFIG                              0x27
#define SX1276_REG_SYNCVALUE1                              0x28
#define SX1276_REG_SYNCVALUE2                              0x29
#define SX1276_REG_SYNCVALUE3                              0x2A
#define SX1276_REG_SYNCVALUE4                              0x2B
#define SX1276_REG_SYNCVALUE5                              0x2C
#define SX1276_REG_SYNCVALUE6                              0x2D
#define SX1276_REG_SYNCVALUE7                              0x2E
#define SX1276_REG_SYNCVALUE8                              0x2F
#define SX1276_REG_PACKETCONFIG1                           0x30
#define SX1276_REG_PACKETCONFIG2                           0x31
#define SX1276_REG_PAYLOADLENGTH                           0x32
#define SX1276_REG_NODEADRS                                0x33
#define SX1276_REG_BROADCASTADRS                           0x34
#define SX1276_REG_FIFOTHRESH                              0x35
// SM settings
#define SX1276_REG_SEQCONFIG1                              0x36
#define SX1276_REG_SEQCONFIG2                              0x37
#define SX1276_REG_TIMERRESOL                              0x38
#define SX1276_REG_TIMER1COEF                              0x39
#define SX1276_REG_TIMER2COEF                              0x3A
// Service settings
#define SX1276_REG_IMAGECAL                                0x3B
#define SX1276_REG_TEMP                                    0x3C
#define SX1276_REG_LOWBAT                                  0x3D
// Status
#define SX1276_REG_IRQFLAGS1                               0x3E
#define SX1276_REG_IRQFLAGS2                               0x3F
// I/O settings
#define SX1276_REG_DIOMAPPING1                             0x40
#define SX1276_REG_DIOMAPPING2                             0x41
// Version
#define SX1276_REG_VERSION                                 0x42
// Additional settings
#define SX1276_REG_PLLHOP                                  0x44
#define SX1276_REG_TCXO                                    0x4B
#define SX1276_REG_PADAC                                   0x4D
#define SX1276_REG_FORMERTEMP                              0x5B
#define SX1276_REG_BITRATEFRAC                             0x5D
#define SX1276_REG_AGCREF                                  0x61
#define SX1276_REG_AGCTHRESH1                              0x62
#define SX1276_REG_AGCTHRESH2                              0x63
#define SX1276_REG_AGCTHRESH3                              0x64
#define SX1276_REG_PLL                                     0x70

#endif // __SX1276_REGS_FSK_H__
