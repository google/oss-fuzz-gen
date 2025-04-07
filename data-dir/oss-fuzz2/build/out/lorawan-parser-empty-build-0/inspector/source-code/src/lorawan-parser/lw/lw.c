#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "aes.h"
#include "cmac.h"
#include "lw.h"
#include "log.h"

void lw_cpy(uint8_t *dest, uint8_t *src, int len);
int lw_check_zero(uint8_t *src, int len);

int lw_mtype_join_accept(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_join_request(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_msg_up(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_msg_down(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_cmsg_up(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_cmsg_down(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_rfu(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);
int lw_mtype_proprietary(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);

typedef int (*lw_mtype_func_p) (lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len);

uint8_t lw_dft_nwkskey[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3c
};

uint8_t lw_dft_appskey[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3c
};

uint8_t lw_dft_appkey[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3c
};

lw_dnonce_t lw_dft_dnonce;

lw_node_t *lw_node;
lw_node_t *lw_node_latest_jr;
lw_node_t lw_node_buf[LW_MAX_NODES];
uint32_t lw_node_num;
uint32_t lw_deveui_cnt;
uint32_t lw_devaddr_cnt;
lw_frame_t lw_dlframe;
lw_config_t lw_config;
bool lw_v11;

const lw_mtype_func_p lwp_mtye_func[] = {
    lw_mtype_join_request,
    lw_mtype_join_accept,
    lw_mtype_msg_up,
    lw_mtype_msg_down,
    lw_mtype_cmsg_up,
    lw_mtype_cmsg_down,
    lw_mtype_rfu,
    lw_mtype_proprietary,
};

/* Data Rate Scheme */
const uint8_t lw_dr_tab_0[16] = {
    LW_DR(SF12, BW125),    // DR0
    LW_DR(SF11, BW125),    // DR1
    LW_DR(SF10, BW125),    // DR2
    LW_DR(SF9, BW125),     // DR3
    LW_DR(SF8, BW125),     // DR4
    LW_DR(SF7, BW125),     // DR5
    LW_DR(SF7, BW250),     // DR7
    LW_DR(FSK, BW125),     // DR8
    LW_DR_RFU,             // DR9
    LW_DR_RFU,             // DR10
    LW_DR_RFU,             // DR11
    LW_DR_RFU,             // DR12
    LW_DR_RFU,             // DR13
    LW_DR_RFU,             // DR14
    LW_DR_RFU,             // DR15
};
const uint8_t lw_dr_tab_1[16] = {

    LW_DR(SF10, BW125),    // DR0
    LW_DR(SF9, BW125),     // DR1
    LW_DR(SF8, BW125),     // DR2
    LW_DR(SF7, BW125),     // DR3
    LW_DR(SF8, BW500),     // DR4
    LW_DR_RFU,             // DR5
    LW_DR_RFU,             // DR6
    LW_DR_RFU,             // DR7
    LW_DR(SF12, BW500),    // DR8
    LW_DR(SF11, BW500),    // DR9
    LW_DR(SF10, BW500),    // DR10
    LW_DR(SF9, BW500),     // DR11
    LW_DR(SF8, BW500),     // DR12
    LW_DR(SF7, BW500),     // DR13
    LW_DR_RFU,             // DR14
    LW_DR_RFU,             // DR15
};
const uint8_t lw_dr_tab_2[16] = {
    LW_DR(SF12, BW125),    // DR0
    LW_DR(SF11, BW125),    // DR1
    LW_DR(SF10, BW125),    // DR2
    LW_DR(SF9, BW125),     // DR3
    LW_DR(SF8, BW125),     // DR4
    LW_DR(SF7, BW125),     // DR5
    LW_DR(SF8, BW500),     // DR6
    LW_DR_RFU,             // DR7
    LW_DR(SF12, BW500),    // DR8
    LW_DR(SF11, BW500),    // DR9
    LW_DR(SF10, BW500),    // DR10
    LW_DR(SF9, BW500),     // DR11
    LW_DR(SF8, BW500),     // DR12
    LW_DR(SF7, BW500),     // DR13
    LW_DR_RFU,             // DR14
    LW_DR_RFU,             // DR15
};
const uint8_t lw_dr_tab_3[16] = {
    LW_DR(SF12, BW125),    // DR0
    LW_DR(SF11, BW125),    // DR1
    LW_DR(SF10, BW125),    // DR2
    LW_DR(SF9, BW125),     // DR3
    LW_DR(SF8, BW125),     // DR4
    LW_DR(SF7, BW125),     // DR5
    LW_DR_RFU,             // DR7
    LW_DR_RFU,             // DR8
    LW_DR_RFU,             // DR9
    LW_DR_RFU,             // DR10
    LW_DR_RFU,             // DR11
    LW_DR_RFU,             // DR12
    LW_DR_RFU,             // DR13
    LW_DR_RFU,             // DR14
    LW_DR_RFU,             // DR15
};

/* LinkAdrReq ChmskCntl */
const uint16_t lw_chmaskcntl_tab_0[8]={
    LW_CMC(0, 15),
    LW_CMC_RFU,
    LW_CMC_RFU,
    LW_CMC_RFU,
    LW_CMC_RFU,
    LW_CMC_RFU,
    LW_CMC_ALL_ON,
    LW_CMC_RFU,
};
const uint16_t lw_chmaskcntl_tab_1[8]={
    LW_CMC(0, 15),
    LW_CMC(16, 31),
    LW_CMC(32, 47),
    LW_CMC(48, 63),
    LW_CMC(64, 71),
    LW_CMC_RFU,
    LW_CMC_ALL_125KHZ_ON,
    LW_CMC_ALL_125KHZ_OFF,
};
const uint16_t lw_chmaskcntl_tab_2[8]={
    LW_CMC(0, 15),
    LW_CMC(16, 31),
    LW_CMC(32, 47),
    LW_CMC(48, 63),
    LW_CMC(64, 79),
    LW_CMC(80, 95),
    LW_CMC_ALL_ON,
    LW_CMC_RFU,
};

const int8_t lw_max_eirp_tab[16] = {
    8, 10, 12, 13, 14, 16, 18, 20, 21, 24, 26, 27, 29, 30, 33, 36
};

#define LW_DR_TAB_EU868                 lw_dr_tab_0
#define LW_DR_TAB_US915                 lw_dr_tab_1
#define LW_DR_TAB_CN779                 LW_DR_TAB_EU868
#define LW_DR_TAB_EU433                 LW_DR_TAB_EU868
#define LW_DR_TAB_AU915                 lw_dr_tab_2
#define LW_DR_TAB_CN470                 lw_dr_tab_3
#define LW_DR_TAB_AS923                 LW_DR_TAB_EU868
#define LW_DR_TAB_KR920                 LW_DR_TAB_CN470
#define LW_DR_TAB_IN865                 LW_DR_TAB_EU868
#define LW_DR_TAB_RU864                 LW_DR_TAB_EU868

#define LW_CHMSKCNTL_TAB_EU868          lw_chmaskcntl_tab_0
#define LW_CHMSKCNTL_TAB_US915          lw_chmaskcntl_tab_1
#define LW_CHMSKCNTL_TAB_CN779          LW_CHMSKCNTL_TAB_EU868
#define LW_CHMSKCNTL_TAB_EU433          LW_CHMSKCNTL_TAB_EU868
#define LW_CHMSKCNTL_TAB_AU915          LW_CHMSKCNTL_TAB_US915
#define LW_CHMSKCNTL_TAB_CN470          lw_chmaskcntl_tab_2
#define LW_CHMSKCNTL_TAB_AS923          LW_CHMSKCNTL_TAB_EU868
#define LW_CHMSKCNTL_TAB_KR920          LW_CHMSKCNTL_TAB_EU868
#define LW_CHMSKCNTL_TAB_IN865          LW_CHMSKCNTL_TAB_EU868
#define LW_CHMSKCNTL_TAB_RU864          LW_CHMSKCNTL_TAB_EU868

const lw_region_t lw_region_tab[] = {
    {
        EU868,
        "EU868",
        LW_DR_TAB_EU868,
        {5, 7},
        LW_CHMSKCNTL_TAB_EU868,
    },
    {
        US915,
        "US915",
        LW_DR_TAB_US915,
        {13, 10},
        LW_CHMSKCNTL_TAB_US915,
    },
    {
        CN779,
        "CN779",
        LW_DR_TAB_CN779,
        {2, 5},
        LW_CHMSKCNTL_TAB_CN779,
    },
    {
        EU433,
        "EU433",
        LW_DR_TAB_EU433,
        {2, 5},
        LW_CHMSKCNTL_TAB_EU433,
    },
    {
        AU915,
        "AU915",
        LW_DR_TAB_AU915,
        {13, 10},
        LW_CHMSKCNTL_TAB_AU915,
    },
    {
        CN470,
        "CN470",
        LW_DR_TAB_CN470,
        {7, 7},
        LW_CHMSKCNTL_TAB_CN470,
    },
    {
        AS923,
        "AS923",
        LW_DR_TAB_AS923,
        {5, 7},
        LW_CHMSKCNTL_TAB_AS923,
    },
    {
        KR920,
        "KR920",
        LW_DR_TAB_KR920,
        {4, 7},
        LW_CHMSKCNTL_TAB_KR920,
    },
    {
        IN865,
        "IN865",
        LW_DR_TAB_IN865,
        {13, 10},
        LW_CHMSKCNTL_TAB_IN865,
    },
    {
        RU864,
        "RU864",
        LW_DR_TAB_RU864,
        {5, 7},
        LW_CHMSKCNTL_TAB_RU864,
    },
};

const lw_region_t *lw_region;

int8_t lw_pow_tab[16] = {
    /* EU868 */
    20,
    14,
    11,
    8,
    5,
    2,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
    LW_POW_RFU,
};

typedef struct{
    uint8_t cmd;
    uint8_t len;
}lw_maccmd_len_t;

const lw_maccmd_len_t lw_node_maccmd_tab[]={
    { MOTE_MAC_LINK_CHECK_REQ,          MOTE_MAC_LEN_LINK_CHECK_REQ },
    { MOTE_MAC_LINK_ADR_ANS,            MOTE_MAC_LEN_LINK_ADR_ANS },
    { MOTE_MAC_DUTY_CYCLE_ANS,          MOTE_MAC_LEN_DUTY_CYCLE_ANS },
    { MOTE_MAC_RX_PARAM_SETUP_ANS,      MOTE_MAC_LEN_RX_PARAM_SETUP_ANS },
    { MOTE_MAC_DEV_STATUS_ANS,          MOTE_MAC_LEN_DEV_STATUS_ANS },
    { MOTE_MAC_NEW_CHANNEL_ANS,         MOTE_MAC_LEN_NEW_CHANNEL_ANS },
    { MOTE_MAC_RX_TIMING_SETUP_ANS,     MOTE_MAC_LEN_RX_TIMING_SETUP_ANS },
    { MOTE_MAC_TX_PARAM_SETUP_ANS,      MOTE_MAC_LEN_TX_PARAM_SETUP_ANS },
    { MOTE_MAC_DL_CHANNEL_ANS,          MOTE_MAC_LEN_DL_CHANNEL_ANS },
    { MOTE_MAC_DEVICE_TIME_REQ,         MOTE_MAC_LEN_DEVICE_TIME_REQ       },
    { MOTE_MAC_PING_SLOT_INFO_REQ,      MOTE_MAC_LEN_PING_SLOT_INFO_REQ },
    { MOTE_MAC_PING_SLOT_FREQ_ANS,      MOTE_MAC_LEN_PING_SLOT_FREQ_ANS },
    { MOTE_MAC_BEACON_TIMING_REQ,       MOTE_MAC_LEN_BEACON_TIMING_REQ },
    { MOTE_MAC_BEACON_FREQ_ANS,         MOTE_MAC_LEN_BEACON_FREQ_ANS },
};

const lw_maccmd_len_t lw_server_maccmd_tab[]={
    { SRV_MAC_LINK_CHECK_ANS,           SRV_MAC_LEN_LINK_CHECK_ANS },
    { SRV_MAC_LINK_ADR_REQ,             SRV_MAC_LEN_LINK_ADR_REQ },
    { SRV_MAC_DUTY_CYCLE_REQ,           SRV_MAC_LEN_DUTY_CYCLE_REQ },
    { SRV_MAC_RX_PARAM_SETUP_REQ,       SRV_MAC_LEN_RX_PARAM_SETUP_REQ },
    { SRV_MAC_DEV_STATUS_REQ,           SRV_MAC_LEN_DEV_STATUS_REQ },
    { SRV_MAC_NEW_CHANNEL_REQ,          SRV_MAC_LEN_NEW_CHANNEL_REQ },
    { SRV_MAC_RX_TIMING_SETUP_REQ,      SRV_MAC_LEN_RX_TIMING_SETUP_REQ },
    { SRV_MAC_TX_PARAM_SETUP_REQ,       SRV_MAC_LEN_TX_PARAM_SETUP_REQ },
    { SRV_MAC_DL_CHANNEL_REQ,           SRV_MAC_LEN_DL_CHANNEL_REQ },
    { SRV_MAC_DEVICE_TIME_ANS,         SRV_MAC_LEN_DEVICE_TIME_ANS       },
    { SRV_MAC_PING_SLOT_INFO_ANS,       SRV_MAC_LEN_PING_SLOT_INFO_ANS },
    { SRV_MAC_PING_SLOT_CHANNEL_REQ,    SRV_MAC_LEN_PING_SLOT_CHANNEL_REQ },
    { SRV_MAC_BEACON_TIMING_ANS,        SRV_MAC_LEN_BEACON_TIMING_ANS },
    { SRV_MAC_BEACON_FREQ_REQ,          SRV_MAC_LEN_BEACON_FREQ_REQ },
};

const uint16_t lw_eu868_lgw_dr_tab[16] = {
    LW_LGW_DR(DR_LORA_SF12, BW_125KHZ),
    LW_LGW_DR(DR_LORA_SF11, BW_125KHZ),
    LW_LGW_DR(DR_LORA_SF10, BW_125KHZ),
    LW_LGW_DR(DR_LORA_SF9, BW_125KHZ),
    LW_LGW_DR(DR_LORA_SF8, BW_125KHZ),
    LW_LGW_DR(DR_LORA_SF7, BW_125KHZ),
    LW_LGW_DR(DR_LORA_SF7, BW_250KHZ),
    0,                                   // FSK
    0xFFFF,
    0xFFFF,
    0xFFFF,
    0xFFFF,
    0xFFFF,
    0xFFFF,
    0xFFFF,
    0xFFFF,
};

const lw_region_t *lw_get_region(lw_band_t band)
{
    int i;
    for(i=0; i<sizeof(lw_region_tab)/sizeof(lw_region_tab[0]); i++){
        if(band == lw_region_tab[i].band){
            return &lw_region_tab[i];
        }
    }
    return &lw_region_tab[0];
}

int8_t lw_get_node_maccmd_len(uint8_t cmd)
{
    int j;
    for (j = 0; j < (sizeof(lw_node_maccmd_tab) / sizeof(lw_maccmd_len_t)); j++) {
        if (lw_node_maccmd_tab[j].cmd == cmd) {
            return lw_node_maccmd_tab[j].len;
        }
    }
    return -1;
}

int8_t lw_get_server_maccmd_len(uint8_t cmd)
{
    int j;
    for (j = 0; j < (sizeof(lw_server_maccmd_tab) / sizeof(lw_maccmd_len_t)); j++) {
        if (lw_server_maccmd_tab[j].cmd == cmd) {
            return lw_server_maccmd_tab[j].len;
        }
    }
    return -1;
}


int lw_init(lw_band_t band)
{
    int i;

    lw_node = NULL;
    lw_node_latest_jr = NULL;
    lw_node_num = 0;
    lw_deveui_cnt = 0;
    lw_devaddr_cnt = 0x01000000;
    memset((uint8_t *)lw_node_buf, 0, sizeof(lw_node_buf));

    //lw_config.rxwin2.dr = 0;          // not used
    lw_config.rxwin2.freq = 869525000;

    lw_region = lw_get_region(band);

    for(i = 0; i<16; i++){
        if(i <= lw_region->power.max_tx_power_index){
            lw_pow_tab[i] = lw_max_eirp_tab[lw_region->power.max_eirp_index] - 2*i;
        }else{
            lw_pow_tab[i] = LW_POW_RFU;
        }
    }

    return 0;
}

lw_node_t *lw_get_node(uint8_t *deveui)
{
    lw_node_t *cur = lw_node;

    for(; cur != NULL; cur = cur->next){
        if(0 == memcmp(deveui, cur->deveui, 8)){
            return cur;
        }
    }

    return NULL;
}

void lw_set_deveui(uint8_t *deveui)
{
    /* Little endian */
    deveui[0] = (uint8_t)(lw_deveui_cnt>>0);
    deveui[1] = (uint8_t)(lw_deveui_cnt>>8);
    deveui[2] = (uint8_t)(lw_deveui_cnt>>16);
    deveui[3] = (uint8_t)(lw_deveui_cnt>>24);
    deveui[4] = 0x00;
    deveui[5] = 0x70;
    deveui[6] = 0x77;
    deveui[7] = 0x6c;
    lw_deveui_cnt++;
}

// None support duplicated devaddr
int lw_add(lw_node_t *node)
{
    int i;
    lw_node_t *cur = lw_node;

    /* Find available buf */
    for(i=0; i<LW_MAX_NODES; i++){
        if(lw_node_buf[i].flag == 0){
            break;
        }
    }

    if( i == LW_MAX_NODES ){
        return LW_ERR_NODE_USED_UP;
    }

    /* Check to make sure devaddr/deveui is not exist */
    for(; cur != NULL; cur = cur->next){
        if( node->mode == OTAA ){
            /* check deveui */
            if(0 == memcmp(node->deveui, cur->deveui, 8)){
                return LW_OK;
            }
        }else{
            /* check devaddr/nwkskey */
            if( node->devaddr.data == cur->devaddr.data ){
                if( 0 == memcmp(node->nwkskey, cur->nwkskey, 16) ){
                    return LW_OK;
                }
            }
        }
    }


    memcpy((uint8_t *)&lw_node_buf[i], (uint8_t *)node, sizeof(lw_node_t));

    if( 0 == lw_check_zero(lw_node_buf[i].deveui, 8) ){
        lw_set_deveui(lw_node_buf[i].deveui);
        memcpy(node->deveui, lw_node_buf[i].deveui, 8);
    }else{
        memcpy(lw_node_buf[i].deveui, node->deveui, 8);
    }
    memcpy(lw_node_buf[i].appeui, node->appeui, 8);

    if(lw_node_buf[i].mode == OTAA){
        /* Allocate Devaddr, NetId, AppNonce */
        lw_node_buf[i].devaddr.data = lw_devaddr_cnt;
        lw_node_buf[i].netid.data = 0;
        lw_node_buf[i].appnonce.data = 0;
        lw_devaddr_cnt++;
    }

    lw_node_buf[i].dlsize = 0;
    lw_node_buf[i].dlbuf = 0;
    lw_node_buf[i].maccmdsize = 0;
    lw_node_buf[i].flag = 1;
    lw_node_buf[i].next = lw_node;
    lw_node = &lw_node_buf[i];

    return LW_OK;
}

int lw_del(uint8_t *deveui)
{
    lw_node_t *cur = lw_node, *pre = lw_node;

    while(cur != NULL){
        if(memcmp(cur->deveui, deveui, 8) == 0){
            cur->flag = 0;
            if(cur == lw_node){
                lw_node = lw_node->next;
            }else{
                pre->next = pre->next->next;
            }
            return LW_OK;
        }
        cur = cur->next;
        pre = cur;
    }

    return LW_ERR_NOT_AVALAIBLE;
}

int lw_add_tx(uint8_t *deveui, uint8_t port, uint8_t *buf, uint16_t size)
{
    lw_node_t *cur = lw_get_node(deveui);
    if(cur == NULL){
        return LW_ERR_UNKOWN_DEVEUI;
    }

    if( ( cur->dlbuf != NULL ) || (cur->dlsize != 0) ){
        return LW_ERR_TX_BUF_NOT_EMPTY;
    }

    cur->dlbuf = malloc(size);
    if( cur->dlbuf == NULL ){
        return LW_ERR_NO_HEAP;
    }

    memcpy(cur->dlbuf, buf, size);
    cur->dlsize = size;
    cur->dlport = port;

    return LW_OK;
}

int lw_set_key(lw_key_grp_t *kgrp)
{
    if(kgrp->flag.bits.nwkskey){
        memcpy(lw_dft_nwkskey, kgrp->nwkskey, 16);
    }
    if(kgrp->flag.bits.appskey){
        memcpy(lw_dft_appskey, kgrp->appskey, 16);
    }
    if(kgrp->flag.bits.appkey){
        memcpy(lw_dft_appkey, kgrp->appkey, 16);
    }
    return LW_OK;
}

int lw_tx_maccmd(uint8_t *deveui, lw_maccmd_t *maccmd)
{
    lw_node_t *cur = lw_get_node(deveui);
    int j, len;

    if(cur == NULL){
        return LW_ERR_UNKOWN_DEVEUI;
    }

    len = 0;
    for(j=0; j<(sizeof(lw_server_maccmd_tab)/sizeof(lw_maccmd_len_t)); j++){
        if( lw_server_maccmd_tab[j].cmd == maccmd->cmd ){
            len = lw_server_maccmd_tab[j].len;
            maccmd->len = len;
            break;
        }
    }

    if(len == 0){
        return LW_ERR_MACCMD;
    }

    if( (cur->maccmdsize + len) > 15 ){
        return LW_ERR_MACCMD;
    }

    memcpy( cur->maccmd+cur->maccmdsize, (uint8_t *)maccmd, len);
    cur->maccmdsize += len;

    return LW_OK;
}

int lw_maccmd_valid(uint8_t mac_header, uint8_t *opts, int len)
{
    int i, j;
    lw_mhdr_t mhdr;

    mhdr.data = mac_header;

    // Traverse all possible commands, if any of them is invalid terminate and return error
    i=0;
    while(i<len){
        if( (mhdr.bits.mtype == LW_MTYPE_MSG_UP) || (mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            for(j=0; j<(sizeof(lw_node_maccmd_tab)/sizeof(lw_maccmd_len_t)); j++){
                if( lw_node_maccmd_tab[j].cmd == opts[i] ){
                    i += lw_node_maccmd_tab[j].len;
                    break;
                }
            }
            if( j == (sizeof(lw_node_maccmd_tab)/sizeof(lw_maccmd_len_t)) ){
                return LW_ERR_MACCMD_LEN;
            }
        }else if( (mhdr.bits.mtype == LW_MTYPE_MSG_DOWN) || (mhdr.bits.mtype == LW_MTYPE_CMSG_DOWN) ){
            for(j=0; j<(sizeof(lw_server_maccmd_tab)/sizeof(lw_maccmd_len_t)); j++){
                if( lw_server_maccmd_tab[j].cmd == opts[i] ){
                    i += lw_server_maccmd_tab[j].len;
                    break;
                }
            }
            if( j == (sizeof(lw_server_maccmd_tab)/sizeof(lw_maccmd_len_t)) ){
                return LW_ERR_MACCMD_LEN;
            }
        }else{
            return LW_ERR_MACCMD;
        }
    }
    return LW_OK;
}

int lw_answer(lw_frame_t *frame, lw_rxpkt_t *rxpkt, lw_txpkt_t *txpkt)
{
    lw_frame_t *dlframe = &lw_dlframe;
    lw_node_t *cur;
    lw_skey_seed_t lw_skey_seed;
    int len;
    bool anwser = false;
    int8_t rxdr, rx1dr = 0;

    memset( (uint8_t *)dlframe, 0, sizeof(lw_frame_t) );

    cur = lw_get_node(frame->deveui);
    if( cur == NULL ){
        return LW_ERR_NOT_AVALAIBLE;
    }

    rx1dr = lw_get_dr(rxpkt->modulation, rxpkt->datarate, rxpkt->bandwidth);
    if(rx1dr < 0){
        return LW_ERR_UNKOWN_DATA_RATE;
    }
    rx1dr -= cur->dlsettings.bits.rx1droft;
    if(rx1dr<DR0){
        rx1dr = DR0;
    }

    memcpy(dlframe->deveui, frame->deveui, 8);

    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_JOIN_REQUEST:
        dlframe->mhdr.bits.mtype = LW_MTYPE_JOIN_ACCEPT;
        dlframe->pl.ja.appnonce.data = cur->appnonce.data;
        dlframe->pl.ja.netid.data = cur->appnonce.data;
        dlframe->pl.ja.devaddr.data = cur->devaddr.data;
        dlframe->pl.ja.dlsettings.data = cur->dlsettings.data;
        dlframe->pl.ja.rxdelay.data = cur->rxdelay.data;

        lw_skey_seed.aeskey = cur->appkey;
        lw_skey_seed.anonce.data = cur->appnonce.data;
        lw_skey_seed.dnonce.data = cur->devnonce.data;
        lw_skey_seed.netid.data = cur->netid.data;
        lw_get_skeys(cur->nwkskey, cur->appskey, &lw_skey_seed);

        anwser = true;
        break;
    case LW_MTYPE_CMSG_UP:
        anwser = true;
        dlframe->pl.mac.fctrl.dl.ack = 1;
    case LW_MTYPE_MSG_UP:
        dlframe->mhdr.bits.mtype = LW_MTYPE_MSG_DOWN;
        dlframe->pl.mac.devaddr.data = cur->devaddr.data;
        if(cur->maccmdsize > 0){
            anwser = true;
            dlframe->pl.mac.fctrl.dl.foptslen = cur->maccmdsize;
            memcpy(dlframe->pl.mac.fopts, cur->maccmd, cur->maccmdsize);
            cur->maccmdsize = 0;
        }
        dlframe->pl.mac.fcnt = cur->dfcnt;
        if(cur->dlsize > 0){
            anwser = true;
            dlframe->pl.mac.fport = cur->dlport;
            memcpy(dlframe->pl.mac.fpl, cur->dlbuf, cur->dlsize);
            dlframe->pl.mac.flen = cur->dlsize;
            free(cur->dlbuf);
            cur->dlbuf = NULL;
            cur->dlsize = 0;
        }
        if(frame->pl.mac.fctrl.ul.adrackreq == 1){
            anwser = true;
        }
        break;
    default:
        return LW_ERR_UNKOWN_FRAME;
    }

    if( (anwser == true) && (lw_pack(dlframe, txpkt->payload, &len) > 0) ){
        txpkt->tx_mode = TIMESTAMPED;
        if( cur->rxdelay.bits.del == 0 ){
            cur->rxdelay.bits.del++;
        }
        txpkt->count_us = rxpkt->count_us + cur->rxdelay.bits.del*1000000;
        if(cur->rxwin == CLASS_A_RX2){
            txpkt->count_us += 1000000;
            txpkt->freq_hz = lw_config.rxwin2.freq;
            rxdr = cur->dlsettings.bits.rx2dr;
        }else{
            txpkt->freq_hz = rxpkt->freq_hz;
            rxdr = rx1dr;
        }
        if(lw_get_rf(rxdr, &txpkt->modulation, &txpkt->datarate,
                     &txpkt->bandwidth, &txpkt->f_dev) < 0){
            return LW_ERR_UNKOWN_DATA_RATE;
        }
        txpkt->rf_chain = 0;
        txpkt->preamble = 8;
        txpkt->coderate = rxpkt->coderate;
        txpkt->rf_power = 14;
        txpkt->invert_pol = true;
        txpkt->no_crc = true;
        txpkt->no_header = false;
        txpkt->size = len;
        cur->dfcnt++;
        return LW_OK;
    }

    return LW_ERR_UNKOWN_FRAME;
}

int lw_pack(lw_frame_t *frame, uint8_t *msg, int *len)
{
    int i, pl_len;
    lw_mic_t mic;
    lw_key_t lw_key;
    lw_skey_seed_t lw_skey_seed;
    lw_node_t *cur;
    uint8_t out[33];

    i=0;
    msg[i++] = frame->mhdr.data;

    if( frame->node == NULL){
        cur = lw_get_node(frame->deveui);
        if( cur == NULL ){
            return LW_ERR_NOT_AVALAIBLE;
        }
    }else{
        cur = frame->node;
    }

    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_JOIN_REQUEST:
        memcpy(msg+i, frame->appeui, 8);
        i+=8;
        memcpy(msg+i, frame->deveui, 8);
        i+=8;
        msg[i++] = (uint8_t)frame->pl.jr.devnonce.data;
        msg[i++] = (uint8_t)(frame->pl.jr.devnonce.data>>8);
        lw_key.aeskey = cur->appkey;
        lw_key.in = msg;
        lw_key.len = i;
        lw_join_mic(&mic, &lw_key);
        memcpy(msg+i, mic.buf, 4);
        frame->mic.data = mic.data;
        i += 4;
        *len = i;
        return i;
    case LW_MTYPE_JOIN_ACCEPT:
        msg[i++] = (uint8_t)(frame->pl.ja.appnonce.data>>0);
        msg[i++] = (uint8_t)(frame->pl.ja.appnonce.data>>8);
        msg[i++] = (uint8_t)(frame->pl.ja.appnonce.data>>16);
        msg[i++] = (uint8_t)(frame->pl.ja.netid.data>>0);
        msg[i++] = (uint8_t)(frame->pl.ja.netid.data>>8);
        msg[i++] = (uint8_t)(frame->pl.ja.netid.data>>16);
        msg[i++] = (uint8_t)(frame->pl.ja.devaddr.data>>0);
        msg[i++] = (uint8_t)(frame->pl.ja.devaddr.data>>8);
        msg[i++] = (uint8_t)(frame->pl.ja.devaddr.data>>16);
        msg[i++] = (uint8_t)(frame->pl.ja.devaddr.data>>24);
        msg[i++] = frame->pl.ja.dlsettings.data;
        msg[i++] = frame->pl.ja.rxdelay.data;
        if(frame->pl.ja.cflist_len == 16){
            memcpy(msg+i, frame->pl.ja.cflist, 16);
            i+=16;
        }
        lw_key.aeskey = cur->appkey;
        lw_key.in = msg;
        lw_key.len = i;
        lw_join_mic(&mic, &lw_key);
        frame->mic.data = mic.data;
        memcpy(msg+i, mic.buf, 4);
        i += 4;
        lw_key.aeskey = cur->appkey;
        lw_key.in = msg+1;
        lw_key.len = i-1;
        lw_join_encrypt(out+1, &lw_key);
        memcpy(msg+1, out+1, lw_key.len);
        *len = i;

        lw_skey_seed.aeskey = cur->appkey;
        lw_skey_seed.anonce = frame->pl.ja.appnonce;
        lw_skey_seed.dnonce = cur->devnonce;
        lw_skey_seed.netid = frame->pl.ja.netid;
        lw_get_skeys(frame->pl.ja.nwkskey, frame->pl.ja.appskey, &lw_skey_seed);
        return i;
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_MSG_DOWN:
    case LW_MTYPE_CMSG_UP:
    case LW_MTYPE_CMSG_DOWN:
        msg[i++] = (uint8_t)(frame->pl.mac.devaddr.data>>0);
        msg[i++] = (uint8_t)(frame->pl.mac.devaddr.data>>8);
        msg[i++] = (uint8_t)(frame->pl.mac.devaddr.data>>16);
        msg[i++] = (uint8_t)(frame->pl.mac.devaddr.data>>24);
        msg[i++] = frame->pl.mac.fctrl.data;
        msg[i++] = (uint8_t)(frame->pl.mac.fcnt>>0);
        msg[i++] = (uint8_t)(frame->pl.mac.fcnt>>8);
        if(frame->pl.mac.fctrl.dl.foptslen > 0){
            memcpy(msg+i, frame->pl.mac.fopts, frame->pl.mac.fctrl.dl.foptslen);
            i+=frame->pl.mac.fctrl.dl.foptslen;
        }

        lw_key.devaddr.data = frame->pl.mac.devaddr.data;
        lw_key.fcnt32 = frame->pl.mac.fcnt;
        switch(frame->mhdr.bits.mtype){
        case LW_MTYPE_MSG_UP:
        case LW_MTYPE_CMSG_UP:
            lw_key.link = LW_UPLINK;
            break;
        case LW_MTYPE_CMSG_DOWN:
        case LW_MTYPE_MSG_DOWN:
            lw_key.link = LW_DOWNLINK;
            break;
        }

        if(frame->pl.mac.flen>0){
            msg[i++] = frame->pl.mac.fport;
            if(frame->pl.mac.fport == 0){
                lw_key.aeskey = cur->nwkskey;
            }else{
                lw_key.aeskey = cur->appskey;
            }
            lw_key.in = frame->pl.mac.fpl;
            lw_key.len = frame->pl.mac.flen;
            pl_len = lw_encrypt(msg+i, &lw_key);
            i += pl_len;
        }

        lw_key.aeskey = cur->nwkskey;
        lw_key.in = msg;
        lw_key.len = i;

        lw_msg_mic(&mic, &lw_key);
        memcpy(msg+i, mic.buf, 4);
        frame->mic.data = mic.data;
        i += 4;
        *len = i;
        break;
    case LW_MTYPE_RFU:
        *len = 0;
        break;
    case LW_MTYPE_PROPRIETARY:
        *len = 0;
        break;
    }
    return *len;
}

int lw_auto_add(lw_frame_t *frame, uint8_t *msg, int len)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;
    lw_node_t endnode;
    int ret, id;
    uint32_t cnt;

    memset(&endnode, 0, sizeof(endnode));

    memcpy(plmic.buf, msg+len-4, 4);

    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_JOIN_REQUEST:
        lw_key.aeskey = lw_dft_appkey;
        lw_key.in = msg;
        lw_key.len = len-4;
        lw_join_mic(&mic, &lw_key);
        if(mic.data != plmic.data){
            return LW_ERR_UNKOWN_FRAME;
        }

        //log_puts(LOG_NORMAL, "AUTO ADD OTAA DEVICE");

        id = LW_JR_OFF_APPEUI;
        memcpy(frame->appeui, msg+id, 8);
        id = LW_JR_OFF_DEVEUI;
        memcpy(frame->deveui, msg+id, 8);

        memset(&endnode, 0, sizeof(lw_node_t));
        endnode.mode = OTAA;
        id = LW_JR_OFF_APPEUI;
        memcpy(endnode.appeui, msg+id, 8);
        id = LW_JR_OFF_DEVEUI;
        memcpy(endnode.deveui, msg+id, 8);
        memcpy(endnode.appkey, lw_dft_appkey, 16);
        lw_add(&endnode);

        ret = lw_mtype_join_request(frame, lw_get_node(frame->deveui), msg, len);
        if(ret == LW_OK){
            lw_node_latest_jr = lw_get_node(frame->deveui);
        }
        return ret;
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_MSG_DOWN:
    case LW_MTYPE_CMSG_UP:
    case LW_MTYPE_CMSG_DOWN:
        lw_key.aeskey = lw_dft_nwkskey;
        lw_key.in = msg;
        lw_key.len = len-4;
        id = 1;
        lw_key.devaddr.data = ( (uint32_t)msg[id++] << 0 );
        lw_key.devaddr.data |= ( (uint32_t)msg[id++] << 8 );
        lw_key.devaddr.data |= ( (uint32_t)msg[id++] << 16 );
        lw_key.devaddr.data |= ( (uint32_t)msg[id++] << 24 );
        switch(frame->mhdr.bits.mtype){
        case LW_MTYPE_MSG_UP:
        case LW_MTYPE_CMSG_UP:
            lw_key.link = LW_UPLINK;
            break;
        case LW_MTYPE_CMSG_DOWN:
        case LW_MTYPE_MSG_DOWN:
            lw_key.link = LW_DOWNLINK;
            break;
        }
        lw_key.fcnt32 = ((uint32_t)msg[LW_DATA_OFF_FCNT+1]<<8) + msg[LW_DATA_OFF_FCNT];

#if 0
        lw_msg_mic(&mic, &lw_key);
#else
        for(cnt=0; cnt<0xFFFF0000; cnt+=0x00010000){
            lw_key.fcnt32 = cnt + ((uint32_t)msg[LW_DATA_OFF_FCNT+1]<<8) + msg[LW_DATA_OFF_FCNT];
            lw_msg_mic(&mic, &lw_key);
            if(mic.data == plmic.data){
                break;
            }
        }
#endif

        if(mic.data != plmic.data){
            return LW_ERR_MIC;
        }

        //log_puts(LOG_NORMAL, "AUTO ADD ABP DEVICE");

        /* Check if  */
        endnode.mode = ABP;
        memset(endnode.appeui, 0, 8);
        memset(endnode.deveui, 0, 8);
        endnode.devaddr.data = lw_key.devaddr.data;
        memcpy(endnode.nwkskey, lw_dft_nwkskey, 16);
        memcpy(endnode.appskey, lw_dft_appskey, 16);
        endnode.ufcnt = lw_key.fcnt32;     // Increase frame counter high 16bits
        endnode.dfcnt = 0;
        endnode.rxwin = CLASS_A_RX2;
        endnode.dlsettings.bits.rx1droft = 0;
        endnode.dlsettings.bits.rx2dr = 0;      // 0 ~ 7
        endnode.rxdelay.bits.del = 1;
        lw_add(&endnode);

        memcpy(frame->deveui, endnode.deveui, 8);
        lw_mtype_msg_up(frame, lw_get_node(frame->deveui), msg, len);
        return LW_OK;
    }
    return LW_ERR_UNKOWN_FRAME;
}

int lw_parse(lw_frame_t *frame, uint8_t *msg, int len)
{
    int id, ret;
    lw_node_t *cur = lw_node;
    lw_devaddr_t devaddr;

    if(len == 0){
        return LW_ERR_PARA;
    }

    memset( (uint8_t *)frame, 0, sizeof(lw_frame_t) );

    frame->mhdr.data = msg[0];
    if(frame->mhdr.bits.mtype>LW_MTYPE_PROPRIETARY){
        return LW_ERR_CMD_UNKNOWN;
    }

    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_JOIN_REQUEST:
        if(len != LW_JR_LEN){
            return LW_ERR_JOINR_LEN;
        }

        id = LW_JR_OFF_APPEUI;
        memcpy(frame->appeui, msg+id, 8);

        id = LW_JR_OFF_DEVEUI;
        memcpy(frame->deveui, msg+id, 8);
        for(; cur != NULL; cur = cur->next){
            if(cur->mode != OTAA){
                continue;
            }
            if(0 != memcmp(frame->appeui, cur->appeui, 8)){
                continue;
            }
            if(0 != memcmp(frame->deveui, cur->deveui, 8)){
                continue;
            }
            ret = lw_mtype_join_request(frame, cur, msg, len);
            if(ret == LW_OK){
                lw_node_latest_jr = cur;
            }
            return ret;
        }
        ret = lw_auto_add(frame, msg, len);
        if(ret == LW_OK){
            return LW_OK;
        }
        break;
    case LW_MTYPE_JOIN_ACCEPT:
        if(lw_node_latest_jr == NULL){
            return LW_ERR_UNKOWN_FRAME;
        }
        return lw_mtype_join_accept(frame, lw_node_latest_jr, msg, len);
        break;
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_MSG_DOWN:
    case LW_MTYPE_CMSG_UP:
    case LW_MTYPE_CMSG_DOWN:
        // TODO: check minimum len
        id = 1;
        devaddr.data = ( (uint32_t)msg[id++] << 0 );
        devaddr.data |= ( (uint32_t)msg[id++] << 8 );
        devaddr.data |= ( (uint32_t)msg[id++] << 16 );
        devaddr.data |= ( (uint32_t)msg[id++] << 24 );
        for(; cur != NULL; cur = cur->next){
            if( (cur->joined || (cur->mode == ABP) ) && ( cur->devaddr.data == devaddr.data ) ){
                ret = lw_mtype_msg_up(frame, cur, msg, len);
                if(ret == LW_OK){
                    return LW_OK;
                }
            }
        }
        return lw_auto_add(frame, msg, len);
    case LW_MTYPE_RFU:
    case LW_MTYPE_PROPRIETARY:
        return LW_ERR_NOT_AVALAIBLE;
    }

    return LW_ERR_UNKOWN_FRAME;
}

int lw_mtype_join_accept(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;
    lw_skey_seed_t lw_skey_seed;
    uint8_t out[LW_JA_LEN_EXT];
    int pl_len;
    int id;

    if( (len != LW_JA_LEN) && (len != LW_JA_LEN_EXT) ){
        return LW_ERR_JOINA_LEN;
    }

    lw_key.aeskey = cur->appkey;
    lw_key.in = buf+1;
    lw_key.len = len-1;
    out[0] = buf[0];
    pl_len = lw_join_decrypt(out+1, &lw_key);

    if(pl_len>0){
        memcpy(plmic.buf, out+len-4, 4);
        lw_key.aeskey = cur->appkey;
        lw_key.in = out;
        lw_key.len = len-4;
        lw_join_mic(&mic, &lw_key);
        if(mic.data != plmic.data){
            return LW_ERR_MIC;
        }
    }

    lw_skey_seed.aeskey = cur->appkey;
    lw_skey_seed.anonce.data = out[LW_JA_OFF_APPNONCE+0];
    lw_skey_seed.anonce.data |= ((uint32_t)out[LW_JA_OFF_APPNONCE+1] << 8);
    lw_skey_seed.anonce.data |= ((uint32_t)out[LW_JA_OFF_APPNONCE+2] << 16);
    lw_skey_seed.dnonce = cur->devnonce;
    lw_skey_seed.netid.data = out[LW_JA_OFF_NETID+0];
    lw_skey_seed.netid.data |= ((uint32_t)out[LW_JA_OFF_NETID+1] << 8);
    lw_skey_seed.netid.data |= ((uint32_t)out[LW_JA_OFF_NETID+2] << 16);
    lw_get_skeys(frame->pl.ja.nwkskey, frame->pl.ja.appskey, &lw_skey_seed);

    id = LW_JA_OFF_APPNONCE;
    frame->pl.ja.appnonce.data = ( (uint32_t)out[id+0] << 0 );
    frame->pl.ja.appnonce.data |= ( (uint32_t)out[id+1] << 8 );
    frame->pl.ja.appnonce.data |= ( (uint32_t)out[id+2] << 16 );

    id = LW_JA_OFF_NETID;
    frame->pl.ja.netid.data = ( (uint32_t)out[id+0] << 0 );
    frame->pl.ja.netid.data |= ( (uint32_t)out[id+1] << 8 );
    frame->pl.ja.netid.data |= ( (uint32_t)out[id+2] << 16 );

    id = LW_JA_OFF_DEVADDR;
    frame->pl.ja.devaddr.data = ( (uint32_t)out[id+0] << 0 );
    frame->pl.ja.devaddr.data |= ( (uint32_t)out[id+1] << 8 );
    frame->pl.ja.devaddr.data |= ( (uint32_t)out[id+2] << 16 );
    frame->pl.ja.devaddr.data |= ( (uint32_t)out[id+3] << 24 );

    id = LW_JA_OFF_DLSET;
    frame->pl.ja.dlsettings.data = out[id];

    if(len == LW_JA_LEN_EXT){
        id = LW_JA_OFF_CFLIST;
        frame->pl.ja.cflist_len = 16;
        memcpy(frame->pl.ja.cflist, out+id, 16);
    }else{
        frame->pl.ja.cflist_len = 0;
    }

    frame->mic.data = mic.data;

    frame->len = len;
    memcpy(frame->buf, out, frame->len);

    memcpy(frame->deveui, cur->deveui, 8);
    memcpy(frame->appeui, cur->appeui, 8);

    cur->joined = true;
    memcpy(cur->nwkskey, frame->pl.ja.nwkskey, 16);
    memcpy(cur->appskey, frame->pl.ja.appskey, 16);
    cur->devaddr.data = frame->pl.ja.devaddr.data;
    cur->netid.data = frame->pl.ja.netid.data;
    cur->appnonce.data = frame->pl.ja.appnonce.data;

    frame->node = cur;

    return LW_OK;
}

int lw_mtype_join_request(lw_frame_t *frame, lw_node_t *cur, uint8_t *msg, int len)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;
    int id;

    memcpy(plmic.buf, msg+len-4, 4);

    if(cur != NULL){
        lw_key.aeskey = cur->appkey;
        lw_key.in = msg;
        lw_key.len = len-4;
        lw_join_mic(&mic, &lw_key);
        if(mic.data != plmic.data){
            return LW_ERR_UNKOWN_FRAME;
        }
        id = LW_JR_OFF_APPEUI;
        memcpy(frame->appeui, msg+id, 8);

        id = LW_JR_OFF_DEVEUI;
        memcpy(frame->deveui, msg+id, 8);

        id = LW_JR_OFF_DEVNONCE;
        frame->pl.jr.devnonce.data = ( (uint32_t)msg[id++] << 0 );
        frame->pl.jr.devnonce.data |= ( (uint32_t)msg[id++] << 8 );

        // Save devnonce, should maintain devnonce list for security issue
        cur->devnonce = frame->pl.jr.devnonce;

        frame->len = len;
        memcpy(frame->buf, msg, len);

        frame->mic.data = mic.data;

        memcpy(frame->deveui, cur->deveui, 8);
        memcpy(frame->appeui, cur->appeui, 8);

        frame->node = cur;
        return LW_OK;
    }

    return LW_ERR_UNKOWN_FRAME;
}

int lw_mtype_msg_up(lw_frame_t *frame, lw_node_t *cur, uint8_t *msg, int len)
{
    int id, foptslen;
    lw_devaddr_t devaddr;
    lw_mic_t plmic;
    uint32_t diff;
    uint16_t fcnt16, fcntlsb, fcntmsb;
    int pl_len = 0;
    int pl_index = 0;
    lw_mic_t mic;
    lw_key_t lw_key;

    // TODO: check minimum len
    if(len < 12){
        return LW_ERR_UNKOWN_FRAME;
    }
    if(cur == NULL){
        return LW_ERR_UNKOWN_FRAME;
    }

    id = 1;
    devaddr.data = ( (uint32_t)msg[id++] << 0 );
    devaddr.data |= ( (uint32_t)msg[id++] << 8 );
    devaddr.data |= ( (uint32_t)msg[id++] << 16 );
    devaddr.data |= ( (uint32_t)msg[id++] << 24 );
    memcpy(plmic.buf, msg+len-4, 4);

    lw_key.aeskey = cur->nwkskey;
    lw_key.in = msg;
    lw_key.len = len-4;
    lw_key.devaddr.data = devaddr.data;
    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_CMSG_UP:
        lw_key.link = LW_UPLINK;
        break;
    case LW_MTYPE_CMSG_DOWN:
    case LW_MTYPE_MSG_DOWN:
        lw_key.link = LW_DOWNLINK;
        break;
    }

    fcnt16 = ((uint32_t)msg[LW_DATA_OFF_FCNT+1]<<8) + msg[LW_DATA_OFF_FCNT];
    fcntlsb = (uint16_t)cur->ufcnt;
    fcntmsb = (uint16_t)(cur->ufcnt>>16);
    if(fcnt16<fcntlsb){
        fcntmsb++;
    }
    lw_key.fcnt32 = ((uint32_t)fcntmsb<<16) + fcnt16;

    lw_msg_mic(&mic, &lw_key);
    if(mic.data != plmic.data){
        if(lw_key.fcnt32 == fcnt16){
            return LW_ERR_MIC;
        }
        lw_key.fcnt32 = fcnt16;
        lw_msg_mic(&mic, &lw_key);
        if(mic.data != plmic.data){
            return LW_ERR_MIC;
        }
    }

    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_CMSG_UP:
        if(cur->ufsum == 0){
            cur->ufsum++;
        }else{
            if(lw_key.fcnt32 > cur->ufcnt){
                diff = lw_key.fcnt32 - cur->ufcnt;
                if(diff == 0){

                }else{
                    cur->uflost += (diff - 1);
                    cur->ufsum++;
                }
            }else if(lw_key.fcnt32 < cur->ufcnt){
                /* Counter is restarted  */
                cur->ufsum++;
            }
        }
        cur->ufcnt = lw_key.fcnt32;
        break;
    }

    frame->pl.mac.fcnt = lw_key.fcnt32;
    frame->pl.mac.fctrl.data = msg[id++];
    foptslen = frame->pl.mac.fctrl.ul.foptslen;

    if( len > (8 + 4 + foptslen) ){
        if( len == (8 + 4 + foptslen + 1) ){
            frame->pl.mac.flen = 0;
            frame->pl.mac.fport = msg[LW_DATA_OFF_FOPTS + foptslen];
            log_puts(LOG_WARN, "PORT (%d) PRESENT WITHOUT PAYLOAD", frame->pl.mac.fport);
        }else{
            frame->pl.mac.fport = msg[LW_DATA_OFF_FOPTS + foptslen];
            pl_index = LW_DATA_OFF_FOPTS + foptslen + 1;
            pl_len  = len - 4 - pl_index;

            if(frame->pl.mac.fport == 0){
                lw_key.aeskey = cur->nwkskey;
            }else{
                lw_key.aeskey = cur->appskey;
            }
            lw_key.in = msg + pl_index;
            lw_key.len = pl_len;
            pl_len = lw_encrypt(frame->pl.mac.fpl, &lw_key);
            if(pl_len<=0){
                return LW_ERR_DECRYPT;
            }
            frame->pl.mac.flen = pl_len;
        }
    }else{
        frame->pl.mac.flen = 0;
    }

    if( (foptslen != 0) && ( (frame->pl.mac.fport == 0) && (frame->pl.mac.flen > 0) ) ){
        return LW_ERR_FOPTS_PORT0;
    }

    if(foptslen != 0){
        memcpy(frame->pl.mac.fopts, msg+LW_DATA_OFF_FOPTS, foptslen);
    }
    frame->pl.mac.devaddr.data = devaddr.data;
    frame->mic.data = plmic.data;

    memcpy(frame->buf, msg, pl_index);        // until port, pl_index equals length of MHDR+FHDR+FPOR
    memcpy(frame->buf + pl_index, frame->pl.mac.fpl, pl_len);   // payload
    memcpy(frame->buf + len - 4, mic.buf, 4); // mic
    frame->len = len;

    memcpy(frame->deveui, cur->deveui, 8);
    memcpy(frame->appeui, cur->appeui, 8);

    frame->node = cur;
    return LW_OK;

}

int lw_mtype_msg_down(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len)
{
    return lw_mtype_msg_up(frame, cur, buf, len);
}

int lw_mtype_cmsg_up(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len)
{
    return lw_mtype_msg_up(frame, cur, buf, len);
}

int lw_mtype_cmsg_down(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len)
{
    return lw_mtype_msg_up(frame, cur, buf, len);
}

int lw_mtype_rfu(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len)
{
    return LW_ERR_NOT_AVALAIBLE;
}

int lw_mtype_proprietary(lw_frame_t *frame, lw_node_t *cur, uint8_t *buf, int len)
{
    return LW_ERR_NOT_AVALAIBLE;
}

/*****************************************************************************/
uint8_t lgw_util_get_sf(uint8_t sf)
{
    int i;
    for (i = 7; i <= 12; i++) {
        if (sf == (1 << (i - 6))) {
            sf = i;
            break;
        }
    }
    return sf;
}

uint16_t lgw_util_get_bw(uint8_t bw)
{
    uint16_t bwreal = bw;
    switch (bw) {
    case BW_125KHZ:
        bwreal = 125;
        break;
    case BW_250KHZ:
        bwreal = 250;
        break;
    case BW_500KHZ:
        bwreal = 500;
        break;
    }
    return bwreal;
}

uint8_t lgw_util_get_cr(uint8_t cr)
{
    uint8_t crreal = cr;
    switch (cr) {
    case CR_LORA_4_5:
        crreal = 5;
        break;
    case CR_LORA_4_6:
        crreal = 6;
        break;
    case CR_LORA_4_7:
        crreal = 7;
        break;
    case CR_LORA_4_8:
        crreal = 8;
        break;
    }
    return crreal;
}

int8_t lw_get_dr(uint8_t mod, uint32_t datarate, uint8_t bw)
{
    int8_t ret = -1;
    int i;
    uint16_t drtab = LW_LGW_DR(datarate, bw);

    /* EU868 */
    if(mod == MOD_FSK){
        ret = DR7;
    }else if(mod == MOD_LORA){
        for(i=0; i<16; i++){
            if(drtab == lw_eu868_lgw_dr_tab[i]){
                ret = i;
                break;
            }
        }
    }

    return ret;
}

int8_t lw_get_rf(uint8_t dr, uint8_t *mod, uint32_t *datarate, uint8_t *bw, uint8_t *fdev)
{
    uint16_t drtab;
    if(dr>DR15){
        return -1;
    }
    drtab = lw_eu868_lgw_dr_tab[dr];
    if(drtab == 0xFFFF){
        return -1;
    }else if(drtab == 0){
        *mod = MOD_FSK;
        *datarate = 50000;
        *fdev = 3;
    }else{
        *mod = MOD_LORA;
        *datarate = (uint8_t)(drtab&0xFF);
        *bw = (uint8_t)((drtab>>8)&0xFF);
    }
    return 0;
}

static char lw_rf_name[30];
const char *lw_get_rf_name(uint8_t mod, uint32_t datarate, uint8_t bw, uint8_t fdev)
{
    lw_rf_name[0] = '\0';
    if (mod == MOD_LORA) {
        sprintf(lw_rf_name, "SF%dBW%d",
                lgw_util_get_sf(datarate),
                lgw_util_get_bw(bw));
    } else {
        sprintf(lw_rf_name, "FSK50K");
    }
    return lw_rf_name;
}

void lw_cpy(uint8_t *dest, uint8_t *src, int len)
{
    int i;
    for(i=0; i<len; i++){
        dest[i] = src[len-1-i];
    }
}

int lw_check_zero(uint8_t *src, int len)
{
    int i;
    for(i=0; i<len; i++){
        if(src[i] != 0){
            return i+1;
        }
    }
    return 0;
}

void lw_write_dw(uint8_t *output, uint32_t input)
{
	uint8_t* ptr = output;

	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input);
}

uint32_t lw_read_dw(uint8_t *buf)
{
	uint32_t ret;

	ret = ( (uint32_t)buf[0] << 0 );
    ret |= ( (uint32_t)buf[1] << 8 );
    ret |= ( (uint32_t)buf[2] << 16 );
    ret |= ( (uint32_t)buf[3] << 24 );

	return ret;
}

void lw_msg_mic(lw_mic_t* mic, lw_key_t *key)
{
    uint8_t b0[LW_KEY_LEN];
    memset(b0, 0 , LW_KEY_LEN);
    b0[0] = 0x49;
    b0[5] = key->link;

    lw_write_dw(b0+6, key->devaddr.data);
    lw_write_dw(b0+10, key->fcnt32);
    b0[15] = (uint8_t)key->len;

	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

void lw_join_mic(lw_mic_t* mic, lw_key_t *key)
{
    AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

/** Use to generate JoinAccept Payload */
int lw_join_encrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_decrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

/** Use to decrypt JoinAccept Payload */
int lw_join_decrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_encrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

void lw_block_xor(uint8_t const l[], uint8_t const r[], uint8_t out[], uint16_t bytes)
{
	uint8_t const* lptr = l;
	uint8_t const* rptr = r;
	uint8_t* optr = out;
	uint8_t const* const end = out + bytes;

	for (;optr < end; lptr++, rptr++, optr++)
		*optr = *lptr ^ *rptr;
}

int lw_encrypt(uint8_t *out, lw_key_t *key)
{
    if (key->len == 0)
		return -1;

	uint8_t A[LW_KEY_LEN];

	uint16_t const over_hang_bytes = key->len%LW_KEY_LEN;
	int blocks = key->len/LW_KEY_LEN;
	if (over_hang_bytes) {
		++blocks;
	}

	memset(A, 0, LW_KEY_LEN);

	A[0] = 0x01; //encryption flags
	A[5] = key->link;

	lw_write_dw(A+6, key->devaddr.data);
	lw_write_dw(A+10, key->fcnt32);

	uint8_t const* blockInput = key->in;
	uint8_t* blockOutput = out;
	uint16_t i;
	for(i = 1; i <= blocks; i++, blockInput += LW_KEY_LEN, blockOutput += LW_KEY_LEN){
		A[15] = (uint8_t)(i);

		aes_context aesContext;
		aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

		uint8_t S[LW_KEY_LEN];
		aes_encrypt(A, S, &aesContext);

		uint16_t bytes_to_encrypt;
		if ((i < blocks) || (over_hang_bytes == 0))
			bytes_to_encrypt = LW_KEY_LEN;
		else
			bytes_to_encrypt = over_hang_bytes;

		lw_block_xor(S, blockInput, blockOutput, bytes_to_encrypt);
	}
	return key->len;
}

void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed)
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
    memset(b, 0, LW_KEY_LEN);
    b[1] = (uint8_t)(seed->anonce.data>>0);
    b[2] = (uint8_t)(seed->anonce.data>>8);
    b[3] = (uint8_t)(seed->anonce.data>>16);
    b[4] = (uint8_t)(seed->netid.data>>0);
    b[5] = (uint8_t)(seed->netid.data>>8);
    b[6] = (uint8_t)(seed->netid.data>>16);
    b[7] = (uint8_t)(seed->dnonce.data>>0);
    b[8] = (uint8_t)(seed->dnonce.data>>8);

    b[0] = 0x01;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, nwkskey, &aesContext );

    b[0] = 0x02;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, appskey, &aesContext );
}

lw_band_t lw_get_band_type(const char *band)
{
    int i;
    for(i=0; i<sizeof(lw_region_tab)/sizeof(lw_region_tab[0]); i++){
        if(0 == strcmp(band, lw_region_tab[i].name)){
            return (lw_band_t)lw_region_tab[i].band;
        }
    }
    return lw_region_tab[0].band;
}

const char *lw_get_band_name(lw_band_t band)
{
    int i;
    for(i=0; i<sizeof(lw_region_tab)/sizeof(lw_region_tab[0]); i++){
        if(band == lw_region_tab[i].band){
            return lw_region_tab[i].name;
        }
    }
    return lw_region_tab[0].name;
}

/*****************************************************************************/
/* Test examples */

static lw_node_t endnode;
static lw_frame_t frame;
static lw_maccmd_t maccmd;

void lw_test(void)
{
    uint8_t appeui_dft[8] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t deveui_dft[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t appeui[] = {
        //0x52, 0x69, 0x73, 0x69, 0x6e, 0x67, 0x48, 0x46,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    uint8_t deveui[] = {
        //0x47, 0x97, 0xc5, 0x34, 0x00, 0x1e, 0x00, 0x34,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    const uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3c
    };

    uint8_t msg[] = {
        0x40, 0xA9, 0x98, 0x3E, 0x01, 0x80, 0xA5, 0x0E,
        0xE0, 0xBC, 0x32, 0x17, 0x06, 0x6B, 0xD7
    };

    uint8_t dlmsg[] = {
        0xA0, 0x88, 0x57, 0x33, 0x01, 0x00, 0x20, 0x00,
        0xE0, 0xBB, 0x31, 0xAD, 0xB6, 0xB7
    };

    uint8_t dlmsg2[] = {
        0xA0, 0x88, 0x57, 0x33, 0x01, 0x00, 0x21, 0x00, 0xE0,
        0x0B, 0x89, 0xE7, 0xF2, 0xBC
    };

    uint8_t jr[] = {
    //    0x00, 0x46, 0x48, 0x67, 0x6E, 0x69, 0x73, 0x69,
    //    0x52, 0x34, 0x00, 0x1E, 0x00, 0x34, 0xC5, 0x97,
    //    0x47, 0x4E, 0x67, 0x33, 0x75, 0x1D, 0x3C
        0x00, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x00, 0x6a, 0xd4, 0x22, 0x79, 0xdd, 0xe7
    };

    uint8_t ja[] = {
    //    0x20, 0x4C, 0x05, 0x9C, 0xE5, 0xCE, 0x26, 0x36,
    //    0xC2, 0x3E, 0x05, 0xBE, 0xAA, 0xC6, 0x4F, 0x26,
    //    0xCB
        0x20, 0x84, 0x84, 0x2e, 0xe3, 0x7c, 0x1b, 0x45,
        0x36, 0x3e, 0xfc, 0xc0, 0x55, 0xe8, 0xf6, 0x3e,
        0x46
    };


    endnode.mode = ABP;
    memcpy(endnode.appeui, appeui_dft, 8);
    memcpy(endnode.deveui, deveui_dft, 8);
    endnode.devaddr.data = 0x013e98a9;
    memcpy(endnode.nwkskey, key, 16);
    memcpy(endnode.appskey, key, 16);
    lw_add(&endnode);

    endnode.mode = OTAA;
    memcpy(endnode.appeui, appeui, 8);
    memcpy(endnode.deveui, deveui, 8);
    memcpy(endnode.appkey, key, 16);
    lw_add(&endnode);

    if(lw_parse(&frame, msg, sizeof(msg)) >= 0){
        lw_log(&frame, msg, sizeof(msg));
    }
    if(lw_parse(&frame, jr, sizeof(jr)) >= 0){
        lw_log(&frame, jr, sizeof(jr));
    }
    if(lw_parse(&frame, ja, sizeof(ja)) >= 0){
        lw_log(&frame, ja, sizeof(ja));
    }
    if(lw_parse(&frame, dlmsg, sizeof(dlmsg)) >= 0){
        lw_log(&frame, dlmsg, sizeof(dlmsg));
    }
    if(lw_parse(&frame, dlmsg2, sizeof(dlmsg2)) >= 0){
        lw_log(&frame, dlmsg2, sizeof(dlmsg2));
    }

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_LINK_CHECK_ANS;
    maccmd.pl.lchk_ans.margin = 0x01;
    maccmd.pl.lchk_ans.gwcnt = 0x0A;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_LINK_ADR_REQ;
    maccmd.pl.ladr_req.dr_txpow.bits.dr = 5;
    maccmd.pl.ladr_req.dr_txpow.bits.txpow = 1;
    maccmd.pl.ladr_req.chmsk[0] = 0x03;
    maccmd.pl.ladr_req.chmsk[1] = 0x00;
    maccmd.pl.ladr_req.redundancy.bits.nbtrans = 1;
    maccmd.pl.ladr_req.redundancy.bits.chmaskcntl = 6;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_DUTY_CYCLE_REQ;
    maccmd.pl.dcap_req.dcpl.bits.maxdc = 5;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_RX_PARAM_SETUP_REQ;
    maccmd.pl.dn2p_req.dlsettings.bits.rx1droft = 1;
    maccmd.pl.dn2p_req.dlsettings.bits.rx2dr = 3;
    maccmd.pl.dn2p_req.freq[0] = 0x34;
    maccmd.pl.dn2p_req.freq[1] = 0x23;
    maccmd.pl.dn2p_req.freq[2] = 0x01;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_DEV_STATUS_REQ;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_NEW_CHANNEL_REQ;
    maccmd.pl.snch_req.chindex = 4;
    maccmd.pl.snch_req.drrange.bits.min = 2;
    maccmd.pl.snch_req.drrange.bits.max = 7;
    maccmd.pl.snch_req.freq[0] = 0x34;
    maccmd.pl.snch_req.freq[1] = 0x34;
    maccmd.pl.snch_req.freq[2] = 0x34;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);

    memset((uint8_t *)&maccmd, 0, sizeof(lw_maccmd_t));
    maccmd.cmd = SRV_MAC_RX_TIMING_SETUP_REQ;
    maccmd.pl.rxts_req.rxtspl.bits.del = 1;
    lw_tx_maccmd(frame.deveui, &maccmd);
    lw_log_maccmd(0xA0, LW_MACCMD_FOPTS, (uint8_t *)&maccmd, maccmd.len);
}


