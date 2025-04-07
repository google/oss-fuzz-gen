#ifndef __LWP_CONFIG_H
#define __LWP_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#include "loragw_reg.h"
#include "loragw_hal.h"
#include "loragw_aux.h"
#if ! defined _WIN32 && ! defined __CYGWIN__
#include "loragw_gps.h"
#include "loragw_lbt.h"
#endif


typedef enum{
    CFLAG_NWKSKEY = (1<<0),
    CFLAG_APPSKEY = (1<<1),
    CFLAG_APPKEY  = (1<<2),
    CFLAG_JOINR   = (1<<3),
    CFLAG_JOINA   = (1<<4),
}config_flag_t;

typedef struct message{
    uint8_t *buf;
    int16_t len;
    struct message *next;
}message_t;

typedef struct{
    uint32_t flag;
    uint8_t nwkskey[16];
    uint8_t appskey[16];
    uint8_t appkey[16];
    uint8_t band;
    bool joinkey;
    uint8_t *joinr;
    uint8_t joinr_size;
    uint8_t *joina;
    uint8_t joina_size;
    message_t *message;
    message_t *maccmd;
}config_t;

//typedef struct motes_abp{
//    uint8_t band;
//    uint8_t devaddr[4];
//    uint8_t nwkskey[16];
//    uint8_t appskey[16];
//    struct motes_abp *next;
//}motes_abp_t;
//
//typedef struct motes_otaa{
//    uint8_t band;
//    uint8_t deveui[8];
//    uint8_t appkey[16];
//    struct motes_otaa *next;
//}motes_otaa_t;

typedef struct{
    struct{
        bool flag;
        struct lgw_conf_board_s conf;
    }board;
    struct{
        bool flag;
        struct lgw_conf_lbt_s conf;
    }lbt;
    struct{
        bool flag;
        uint32_t tx_freq_max;
        uint32_t tx_freq_min;
        struct lgw_conf_rxrf_s conf;
    }radio[2];
    struct{
        bool flag;
        struct lgw_conf_rxif_s conf;
    }chan[10];
    struct{
        bool flag;
        int gain;
    }antenna;
    struct{
        bool flag;
        struct lgw_tx_gain_lut_s conf;
    }txlut;

    struct{
        bool flag;
        uint8_t buf[8];
    } gwid;

    struct{
        bool flag;
        char *address;
        struct{
            uint16_t port;
        }up;
        struct{
            uint16_t port;
        }down;
    }server;

    int keepalive_interval;
    int stat_interval;
    int push_timeout_ms;

    struct{
        bool flag;
        uint32_t freq;
        uint32_t period;
    }beacon;

    struct{
        bool flag;
        bool fake;
        float longitude;
        float latitude;
        float altitude;
        char *device;
    }gps;

    struct{
        bool flag;
        uint8_t buf[6];
    }mac_addr;
}config_lgw_t;

int config_parse(const char *file, config_t *config);
void config_free(config_t *config);
int config_lgw_parse(char *file, config_lgw_t *lgw);
void config_lgw_free(config_lgw_t *lgw);
int config_lgw_board_parse(char *file, config_lgw_t *lgw);
void conf_log_lgw(config_lgw_t *lgw);

#endif // __CONFIG_H
