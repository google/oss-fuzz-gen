#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "parson.h"
#include "conf.h"
#include "log.h"
#include "str2hex.h"
#include "lw.h"

void pl_insert(message_t **head, message_t *new_node)
{
    message_t *tmp;

    if(*head == NULL){
        *head = new_node;
    }else{
        tmp = *head;
        while(tmp->next != NULL){
            tmp = tmp->next;
        }
        tmp->next = new_node;
    }
}

void pl_free(message_t **head)
{
    message_t *curr;

    while ((curr = *head) != NULL) { // set curr to head, stop if list empty.
        *head = (*head)->next;          // advance head to next element.
        if(curr->buf != NULL){
            free(curr->buf);
        }
        free(curr);                // delete saved pointer.
    }
    *head = NULL;
}

void pl_print(message_t *head)
{
    int i = 0;

    while(head != NULL){
        char buf[100];
        char len[10];
        sprintf(buf, " %d MESSAGE:\t", i);
        sprintf(len, "<%d>", head->len);
        log_puts(LOG_NORMAL, "%15s%6s %H", buf, len, head->buf, head->len);
        head = head->next;
        i++;
    }
}

void maccmd_print(message_t *head)
{
    int i = 0;

    while(head != NULL){
        char buf[100];
        char len[10];
        sprintf(buf, " %d MACCMD:\t", i);
        sprintf(len, "<%d>", head->len-1);
        log_puts(LOG_NORMAL, "%15s%6s [%02X] %H", buf, len, head->buf[0], head->buf+1, head->len-1);
        head = head->next;
        i++;
    }
}

void config_free(config_t *config)
{
    config->flag = 0;
    if(config->joina != NULL){
        free(config->joina);
    }
    if(config->joinr != NULL){
        free(config->joinr);
    }
    pl_free(&config->message);
    pl_free(&config->maccmd);
}

int config_parse(const char *file, config_t *config)
{
    JSON_Value *jvroot;
    JSON_Object *joroot;
    JSON_Object *jomaccmd;
    JSON_Array *jarray;
    JSON_Value_Type jtype;
    const char *string;
    int ret;
    int i;
    char sbuf[100], slen[10];

    if(file == NULL){
        return -1;
    }

    /** Clear all flags */
    config_free(config);

    /* parsing json and validating output */
    jvroot = json_parse_file_with_comments(file);
    jtype = json_value_get_type(jvroot);
    if (jtype != JSONObject) {
        return -1;
    }
    joroot = json_value_get_object(jvroot);

    string = json_object_get_string(joroot, "band");
    if(string != NULL){
        config->band = lw_get_band_type(string);
    }

    string = json_object_dotget_string(joroot, "key.nwkskey");
    if(string != NULL){
        if(str2hex(string, config->nwkskey, 16) == 16){
            config->flag |= CFLAG_NWKSKEY;
        }
    }

    string = json_object_dotget_string(joroot, "key.appskey");
    if(string != NULL){
        if(str2hex(string, config->appskey, 16) == 16){
            config->flag |= CFLAG_APPSKEY;
        }
    }

    string = json_object_dotget_string(joroot, "key.appkey");
    if(string != NULL){
        if(str2hex(string, config->appkey, 16) == 16){
            config->flag |= CFLAG_APPKEY;
        }
    }

    ret = json_object_dotget_boolean(joroot, "join.key");
    if(ret==0){
        //printf("Join key false\n");
        config->joinkey = false;
    }else if(ret==1){
        //printf("Join key true\n");
        config->joinkey = true;
    }else{
        //printf("Unknown join key value\n");
        config->joinkey = false;
    }

    string = json_object_dotget_string(joroot, "join.request");
    if(string != NULL){
        uint8_t tmp[255];
        int len;
        len = str2hex(string, tmp, 255);
        if(len>0){
            config->flag |= CFLAG_JOINR;
            config->joinr = malloc(len);
            if(config->joinr == NULL){
                return -2;
            }
            config->joinr_size = len;
            memcpy(config->joinr, tmp, config->joinr_size);
        }
    }

    string = json_object_dotget_string(joroot, "join.accept");
    if(string != NULL){
        uint8_t tmp[255];
        int len;
        len = str2hex(string, tmp, 255);
        if(len>0){
            config->flag |= CFLAG_JOINA;
            config->joina = malloc(len);
            if(config->joina == NULL){
                return -3;
            }
            config->joina_size = len;
            memcpy(config->joina, tmp, config->joina_size);
        }
    }

    jarray = json_object_get_array(joroot, "messages");
    if(jarray != NULL){
        uint8_t tmp[255];
        for (i = 0; i < json_array_get_count(jarray); i++) {
            string = json_array_get_string(jarray, i);
            if(string!=NULL){
                int len = str2hex(string, tmp, 255);
                if(len>0){
                    message_t *pl = malloc(sizeof(message_t));
                    memset(pl, 0, sizeof(message_t));
                    if(pl == NULL){
                        return -3;
                    }
                    pl->buf = malloc(len);
                    if(pl->buf == NULL){
                        return -3;
                    }
                    pl->len = len;
                    memcpy(pl->buf, tmp, pl->len);
                    pl_insert(&config->message, pl);
                }else{
                    log_puts(LOG_WARN, "Messages[%d] \"%s\" is not hex string\n", i, string);

                }
            }else{
                log_puts(LOG_WARN, "Messages item %d is not string\n", i);
            }
        }
    }else{
        log_puts(LOG_WARN, "Can't get \"messages\" payload array\n");
    }

    jarray = json_object_get_array(joroot, "maccommands");
    if(jarray != NULL){
        uint8_t mhdr;
        int len;
        uint8_t tmp[255];
        for (i = 0; i < json_array_get_count(jarray); i++) {
            jomaccmd = json_array_get_object(jarray, i);
            string = json_object_get_string(jomaccmd, "MHDR");
            if(string != NULL){
                len = str2hex(string, &mhdr, 1);
                if(len != 1){
                    log_puts(LOG_WARN, "\"maccommands\"[%d].MHDR \"%s\" must be 1 byte hex string\n", i, string);
                    continue;
                }
            }else{
                string = json_object_get_string(jomaccmd, "direction");
                if(string != NULL){
                    int j;
                    len = strlen(string);
                    if(len>200){
                        log_puts(LOG_WARN, "\"maccommands\"[%d].direction \"%s\" too long\n", i, string);
                        continue;
                    }
                    for(j=0; j<len; j++){
                        tmp[j] = tolower(string[j]);
                    }
                    tmp[j] = '\0';
                    if(0==strcmp((char *)tmp, "up")){
                        mhdr = 0x80;
                    }else if(0==strcmp((char *)tmp, "down")){
                        mhdr = 0xA0;
                    }else{
                        log_puts(LOG_WARN, "\"maccommands\"[%d].MHDR \"%s\" must be 1 byte hex string\n", i, string);
                        continue;
                    }
                }else{
                    log_puts(LOG_WARN, "Can't recognize maccommand direction\n");
                    continue;
                }
            }
            string = json_object_get_string(jomaccmd, "command");
            if(string != NULL){
                len = str2hex(string, tmp, 255);
                if(len <= 0){
                    log_puts(LOG_WARN, "\"maccommands\"[%d].command \"%s\" is not hex string\n", i, string);
                    continue;
                }
            }else{
                log_puts(LOG_WARN, "c\"maccommands\"[%d].command is not string\n", i);
                continue;
            }
            message_t *pl = malloc(sizeof(message_t));
            memset(pl, 0, sizeof(message_t));
            if(pl == NULL){
                return -3;
            }
            pl->buf = malloc(len+1);
            if(pl->buf == NULL){
                return -3;
            }
            pl->len = len+1;
            pl->buf[0] = mhdr;
            pl->next = 0;
            memcpy(pl->buf+1, tmp, pl->len-1);
            pl_insert(&config->maccmd, pl);
        }
    }

    log_line();
    log_puts(LOG_NORMAL, "%15s %s","BAND:\t", lw_get_band_name(config->band));
    sprintf(sbuf, "NWKSKEY:\t");
    sprintf(slen, "<%d>", 16);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->nwkskey, 16);
    sprintf(sbuf, "APPSKEY:\t");
    sprintf(slen, "<%d>", 16);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->appskey, 16);
    sprintf(sbuf, "APPKEY:\t");
    sprintf(slen, "<%d>", 16);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->appkey, 16);
    sprintf(sbuf, "JOINR:\t");
    sprintf(slen, "<%d>", config->joinr_size);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->joinr, config->joinr_size);
    sprintf(sbuf, "JOINA:\t");
    sprintf(slen, "<%d>", config->joina_size);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->joina, config->joina_size);
    pl_print(config->message);
    maccmd_print(config->maccmd);

    json_value_free(jvroot);
    return 0;
}
/*
    Configure

    if (lgw_board_setconf(boardconf) != LGW_HAL_SUCCESS) {
        MSG("WARNING: Failed to configure board\n");
    }

    if (lgw_lbt_setconf(lbtconf) != LGW_HAL_SUCCESS) {
        MSG("WARNING: Failed to configure lbt\n");
    }

    if (lgw_txgain_setconf(&txlut) != LGW_HAL_SUCCESS) {
        MSG("WARNING: Failed to configure concentrator TX Gain LUT\n");
    }
*/

int config_lgw_parse(char *file, config_lgw_t *lgw)
{
    JSON_Value *jroot;
    JSON_Object *josx1301;
    JSON_Object *jogw;
    JSON_Value *jv;
    JSON_Object *jo = NULL;
    const char *string;
    char param_name[32];
    uint32_t sf, bw = 0, fdev = 0;
    int i, hlen;

    if(file == NULL){
        return -1;
    }

    memset(lgw, 0, sizeof(config_lgw_t));

    /* parsing json and validating output */
    jroot = json_parse_file_with_comments(file);
    if(json_value_get_type(jroot) != JSONObject) {
        return -1;
    }
    josx1301 = json_object_get_object(json_value_get_object(jroot), "SX1301_conf");
    if(josx1301 == NULL){
        return -2;
    }

    jv = json_object_dotget_value(josx1301, "lorawan_public");
    if(json_value_get_type(jv) == JSONBoolean){
        lgw->board.conf.clksrc = 0;
        lgw->board.conf.lorawan_public = json_value_get_boolean(jv);
        jv = json_object_dotget_value(josx1301, "clksrc");
        if(json_value_get_type(jv) == JSONNumber){
            lgw->board.conf.clksrc =  (uint8_t)json_value_get_number(jv);
        }
        lgw->board.flag = true;
    }

    jv = json_object_dotget_value(josx1301, "lbt_cfg");
    if(json_value_get_type(jv) == JSONObject){
        jo = json_value_get_object(jv);

        lgw->lbt.flag = true;

        jv = json_object_dotget_value(jo, "enable");
        if (json_value_get_type(jv) == JSONBoolean) {
            lgw->lbt.conf.enable = (bool)json_value_get_boolean(jv);
        }
        jv = json_object_dotget_value(jo, "rssi_target");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->lbt.conf.rssi_target = (uint8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "nb_channel");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->lbt.conf.nb_channel = (uint8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "start_freq");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->lbt.conf.start_freq = (uint32_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "scan_time_us");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->lbt.conf.scan_time_us = (uint32_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "tx_delay_1ch_us");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->lbt.conf.tx_delay_1ch_us = (uint32_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "tx_delay_2ch_us");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->lbt.conf.tx_delay_2ch_us = (uint32_t)json_value_get_number(jv);
        }
    }

    jv = json_object_get_value(josx1301, "antenna_gain");
    if (json_value_get_type(jv) == JSONNumber) {
        lgw->antenna.gain = (int8_t)json_value_get_number(jv);
        lgw->antenna.flag = true;
    }

    for (i = 0; i < TX_GAIN_LUT_SIZE_MAX; i++) {
        snprintf(param_name, sizeof param_name, "tx_lut_%i", i);
        jv = json_object_dotget_value(josx1301, param_name);
        if(json_value_get_type(jv) != JSONObject){
            continue;
        }

        jo = json_value_get_object(jv);
        lgw->txlut.conf.size++;

        jv = json_object_dotget_value(jo, "rf_power");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].rf_power = (int8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "dac_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].dac_gain = (uint8_t)json_value_get_number(jv);
        }else{
            lgw->txlut.conf.lut[i].dac_gain = 3; /* This is the only dac_gain supported for now */
        }
        jv = json_object_dotget_value(jo, "dig_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].dig_gain = (uint8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "mix_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].mix_gain = (uint8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "pa_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].pa_gain = (uint8_t)json_value_get_number(jv);
        }
    }

    for (i = 0; i < LGW_RF_CHAIN_NB; ++i) {
        snprintf(param_name, sizeof param_name, "radio_%i", i);
        jv = json_object_get_value(josx1301, param_name);
        if (json_value_get_type(jv) != JSONObject) {
            continue;
        }
        lgw->radio[i].flag = true;
        jo = json_value_get_object(jv);

        jv = json_object_dotget_value(jo, "enable");
        if(json_value_get_type(jv) == JSONBoolean){
            lgw->radio[i].conf.enable = (bool)json_value_get_boolean(jv);
        }
        if(lgw->radio[i].conf.enable == false){
            continue;
        }

        jv = json_object_dotget_value(jo, "freq");
        if(json_value_get_type(jv) == JSONNumber){
            lgw->radio[i].conf.freq_hz = (uint32_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "rssi_offset");
        if(json_value_get_type(jv) == JSONNumber){
            lgw->radio[i].conf.rssi_offset = (float)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "type");
        if(json_value_get_type(jv) == JSONString){
            string = json_value_get_string(jv);
            if(!strncmp(string, "SX1255", 6)) {
                lgw->radio[i].conf.type = LGW_RADIO_TYPE_SX1255;
            }else if (!strncmp(string, "SX1257", 6)){
                lgw->radio[i].conf.type = LGW_RADIO_TYPE_SX1257;
            }else{
                lgw->radio[i].conf.type = LGW_RADIO_TYPE_SX1257;
            }
        }

        jv = json_object_dotget_value(jo, "tx_enable");
        if(json_value_get_type(jv) == JSONBoolean){
            lgw->radio[i].conf.tx_enable = (bool)json_value_get_boolean(jv);
            if(lgw->radio[i].conf.tx_enable){
                jv = json_object_dotget_value(jo, "tx_freq_min");
                if(json_value_get_type(jv) == JSONNumber){
                    lgw->radio[i].tx_freq_min = (uint32_t)json_value_get_number(jv);
                }
                jv = json_object_dotget_value(jo, "tx_freq_max");
                if(json_value_get_type(jv) == JSONNumber){
                    lgw->radio[i].tx_freq_max = (uint32_t)json_value_get_number(jv);
                }
            }
        }
    }

    for(i = 0; i < LGW_MULTI_NB; ++i){
        snprintf(param_name, sizeof param_name, "chan_multiSF_%i", i);
        jv = json_object_get_value(josx1301, param_name);
        if (json_value_get_type(jv) != JSONObject) {
            continue;
        }
        jo = json_value_get_object(jv);

        jv = json_object_dotget_value(jo, "enable");
        if(json_value_get_type(jv) == JSONBoolean){
            lgw->chan[i].conf.enable = (bool)json_value_get_boolean(jv);
            if(lgw->chan[i].conf.enable == false){
                continue;
            }
        }
        if(lgw->chan[i].conf.enable){
            jv = json_object_dotget_value(jo, "radio");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[i].conf.rf_chain = (uint32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "if");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[i].conf.freq_hz = (int32_t)json_value_get_number(jv);
            }
        }
    }

    jv = json_object_get_value(josx1301, "chan_Lora_std");
    if (json_value_get_type(jv) == JSONObject) {
        jo = json_value_get_object(jv);
        jv = json_object_dotget_value(jo, "enable");
        if(json_value_get_type(jv) == JSONBoolean){
            lgw->chan[8].conf.enable = (bool)json_value_get_boolean(jv);
        }
        if(lgw->chan[8].conf.enable){
            jv = json_object_dotget_value(jo, "radio");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[8].conf.rf_chain = (uint32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "if");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[8].conf.freq_hz = (int32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "bandwidth");
            if(json_value_get_type(jv) == JSONNumber){
                bw = (uint32_t)json_value_get_number(jv);
                switch(bw) {
                    case 500000: bw = BW_500KHZ; break;
                    case 250000: bw = BW_250KHZ; break;
                    case 125000: bw = BW_125KHZ; break;
                    default: bw = BW_UNDEFINED;
                }
                lgw->chan[8].conf.bandwidth = bw;
            }
            jv = json_object_dotget_value(jo, "spread_factor");
            if(json_value_get_type(jv) == JSONNumber){
                sf = (uint32_t)json_value_get_number(jv);
                switch(sf) {
                    case  7: sf = DR_LORA_SF7;  break;
                    case  8: sf = DR_LORA_SF8;  break;
                    case  9: sf = DR_LORA_SF9;  break;
                    case 10: sf = DR_LORA_SF10; break;
                    case 11: sf = DR_LORA_SF11; break;
                    case 12: sf = DR_LORA_SF12; break;
                    default: sf = DR_UNDEFINED;
                }
                lgw->chan[8].conf.datarate = sf;
            }
        }
    }

    jv = json_object_get_value(josx1301, "chan_FSK");
    if (json_value_get_type(jv) == JSONObject) {
        jo = json_value_get_object(jv);
        jv = json_object_dotget_value(jo, "enable");
        if(json_value_get_type(jv) == JSONBoolean){
            lgw->chan[9].conf.enable = (bool)json_value_get_boolean(jv);
        }
        if(lgw->chan[9].conf.enable){
            jv = json_object_dotget_value(jo, "radio");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[9].conf.rf_chain = (uint32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "if");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[9].conf.freq_hz = (int32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "bandwidth");
            if(json_value_get_type(jv) == JSONNumber){
                bw = (uint32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "freq_deviation");
            if(json_value_get_type(jv) == JSONNumber){
                fdev = (uint32_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "datarate");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->chan[9].conf.datarate = (uint32_t)json_value_get_number(jv);
            }
            if ((bw == 0) && (fdev != 0)) {
                bw = 2 * fdev + lgw->chan[9].conf.datarate;
            }
            if      (bw == 0)      bw = BW_UNDEFINED;
            else if (bw <= 7800)   bw = BW_7K8HZ;
            else if (bw <= 15600)  bw = BW_15K6HZ;
            else if (bw <= 31200)  bw = BW_31K2HZ;
            else if (bw <= 62500)  bw = BW_62K5HZ;
            else if (bw <= 125000) bw = BW_125KHZ;
            else if (bw <= 250000) bw = BW_250KHZ;
            else if (bw <= 500000) bw = BW_500KHZ;
            else bw = BW_UNDEFINED;
            lgw->chan[9].conf.bandwidth = bw;
        }
    }

    jogw = json_object_get_object(json_value_get_object(jroot), "gateway_conf");
    if(jogw == NULL){
        log_puts(LOG_NORMAL, "ERROR");
        return -2;
    }

    jv = json_object_get_value(jogw, "gps_tty_path");
    if(json_value_get_type(jv) == JSONString){
        string = json_value_get_string(jv);
        lgw->gps.device = malloc(strlen(string)+1);
        if(lgw->gps.device != NULL){
            strcpy(lgw->gps.device, string);
            lgw->gps.flag = true;
            jv = json_object_dotget_value(jo, "fake_gps");
            if(json_value_get_type(jv) == JSONBoolean){
                lgw->gps.fake = (bool)json_value_get_boolean(jv);
            }
            jv = json_object_dotget_value(jo, "ref_longitude");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->gps.longitude = (float)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "ref_latitude");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->gps.latitude = (float)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "ref_altitude");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->gps.altitude = (float)json_value_get_number(jv);
            }
        }
    }

    jv = json_object_get_value(jogw, "server_address");
    if(json_value_get_type(jv) == JSONString){
        string = json_value_get_string(jv);
        lgw->server.address = malloc(strlen(string)+1);
        if(lgw->server.address != NULL){
            strcpy(lgw->server.address, string);
            lgw->server.flag = true;
            jv = json_object_dotget_value(jo, "serv_port_up");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->server.up.port = (uint16_t)json_value_get_number(jv);
            }
            jv = json_object_dotget_value(jo, "serv_port_down");
            if(json_value_get_type(jv) == JSONNumber){
                lgw->server.down.port = (uint16_t)json_value_get_number(jv);
            }
        }
    }

    jv = json_object_get_value(jogw, "beacon_period");
    if(json_value_get_type(jv) == JSONNumber){
        lgw->beacon.period = (uint32_t)json_value_get_number(jv);
        jv = json_object_get_value(jogw, "beacon_freq_hz");
        if(json_value_get_type(jv) == JSONNumber){
            lgw->beacon.freq = (uint32_t)json_value_get_number(jv);
            lgw->beacon.flag = true;
        }
    }

    //"gateway_ID": "AA555A0000000000",
    jv = json_object_get_value(jogw, "gateway_ID");
    if(json_value_get_type(jv) == JSONString){
        string = json_value_get_string(jv);
        hlen = str2hex(string, lgw->gwid.buf, 8);
        if(hlen == 8){
            lgw->gwid.flag = true;
        }
    }

    json_value_free(jv);

    return 0;
}

int config_lgw_board_parse(char *file, config_lgw_t *lgw)
{
    JSON_Value *jroot;
    JSON_Object *josx1301;
    JSON_Value *jv;
    JSON_Object *jo;
    char param_name[32];
    int i;
    bool txlut_flag = false;

    if(file == NULL){
        return -1;
    }

    /* parsing json and validating output */
    jroot = json_parse_file_with_comments(file);
    if(json_value_get_type(jroot) != JSONObject) {
        return -1;
    }
    josx1301 = json_object_get_object(json_value_get_object(jroot), "SX1301_conf");
    if(josx1301 == NULL){
        return -2;
    }

    for (i = 0; i < LGW_RF_CHAIN_NB; ++i) {
        snprintf(param_name, sizeof param_name, "radio_%i", i);
        jv = json_object_get_value(josx1301, param_name);
        if (json_value_get_type(jv) != JSONObject) {
            continue;
        }
        jo = json_value_get_object(jv);
        jv = json_object_dotget_value(jo, "rssi_offset");
        if(json_value_get_type(jv) == JSONNumber){
            lgw->radio[i].conf.rssi_offset = (float)json_value_get_number(jv);
        }
    }

    for (i = 0; i < TX_GAIN_LUT_SIZE_MAX; i++) {
        snprintf(param_name, sizeof param_name, "tx_lut_%i", i);
        jv = json_object_dotget_value(josx1301, param_name);
        if(json_value_get_type(jv) != JSONObject){
            continue;
        }
        if(txlut_flag == false){
            txlut_flag = true;
            memset(&lgw->txlut.conf, 0, sizeof(struct lgw_tx_gain_lut_s));
        }
        jo = json_value_get_object(jv);
        lgw->txlut.conf.size++;

        jv = json_object_dotget_value(jo, "rf_power");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].rf_power = (int8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "dac_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].dac_gain = (uint8_t)json_value_get_number(jv);
        }else{
            lgw->txlut.conf.lut[i].dac_gain = 3; /* This is the only dac_gain supported for now */
        }
        jv = json_object_dotget_value(jo, "dig_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].dig_gain = (uint8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "mix_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].mix_gain = (uint8_t)json_value_get_number(jv);
        }
        jv = json_object_dotget_value(jo, "pa_gain");
        if (json_value_get_type(jv) == JSONNumber) {
            lgw->txlut.conf.lut[i].pa_gain = (uint8_t)json_value_get_number(jv);
        }
    }

    return 0;
}

void conf_log_lgw(config_lgw_t *lgw)
{
    int i;

    log_line();
    if(lgw->board.flag){
        log_puts(LOG_NORMAL, "LoRaWAN %s", lgw->board.conf.lorawan_public?"PUBLIC":"PRIVATE");
        log_puts(LOG_NORMAL, "CLOCK SOURCE RADIO %s", lgw->board.conf.clksrc==0?"A":"B");
    }

    if(lgw->lbt.flag){
        log_puts(LOG_NORMAL, "LBT %s", lgw->lbt.conf.enable?"ON":"OFF");
        log_puts(LOG_NORMAL, "LBT TARGET RSSI %d", lgw->lbt.conf.rssi_target);
        log_puts(LOG_NORMAL, "LBT CHANNELS %d", lgw->lbt.conf.nb_channel);
        log_puts(LOG_NORMAL, "LBT START FREQ %d", lgw->lbt.conf.start_freq);
        log_puts(LOG_NORMAL, "LBT SCAN TIME %d", lgw->lbt.conf.scan_time_us);
        log_puts(LOG_NORMAL, "LBT TX DELAY 1CH %dus", lgw->lbt.conf.tx_delay_1ch_us);
        log_puts(LOG_NORMAL, "LBT TX DELAY 2CH %dus", lgw->lbt.conf.tx_delay_2ch_us);
    }

    if(lgw->antenna.flag){
        log_puts(LOG_NORMAL, "ANTENNA GAIN %d dBi", lgw->antenna.gain);
    }

    log_puts(LOG_NORMAL, "TXLUT SIZE %d", lgw->txlut.conf.size);
    log_puts(LOG_NORMAL, "           RF DAC DIG MIX  PA");
    for(i=0; i<16; i++){
        struct lgw_tx_gain_s *p = &lgw->txlut.conf.lut[i];
        log_puts(LOG_NORMAL, "TXLUT%4d%4d%4d%4d%4d%4d", i, p->rf_power, p->dac_gain, p->dig_gain, p->mix_gain, p->pa_gain);
    }

    for(i=0; i<LGW_RF_CHAIN_NB; i++){
        struct lgw_conf_rxrf_s *p = &lgw->radio[i].conf;
        log_puts(LOG_NORMAL, "RADIO %c %s %s %d %.2f TX %s", 'A'+i, p->enable?"ON":"OFF", p->type==1?"SX1255":"SX1257", \
                 p->freq_hz,p->rssi_offset,p->tx_enable?"ON":"OFF");
    }

    for(i=0; i<LGW_MULTI_NB+2; i++){
        struct lgw_conf_rxif_s *p = &lgw->chan[i].conf;
        log_puts(LOG_NORMAL, "CHAN%4d %s %d, %d, %d, RADIO%d, %d, %X", i, p->enable?"ON":"OFF", p->freq_hz, p->bandwidth, p->datarate, p->rf_chain, p->sync_word_size, p->sync_word);
    }

    if(lgw->gps.flag){
        if(lgw->gps.device){
            log_puts(LOG_NORMAL, "GPS DEVICE %s", lgw->gps.device);
        }
        log_puts(LOG_NORMAL, "GPS FAKE %s", lgw->gps.fake?"ON":"OFF");
        log_puts(LOG_NORMAL, "GPS LONG %f LAT %f ALT %f", lgw->gps.longitude, lgw->gps.latitude, lgw->gps.altitude);
    }

    if(lgw->server.flag){
        if(lgw->server.address){
            log_puts(LOG_NORMAL, "SERVER ADDRESS %s UP %d DOWN %d", lgw->server.address, lgw->server.up.port, lgw->server.down.port);
        }
    }

    if(lgw->gwid.flag){
        log_puts(LOG_NORMAL, "GWID: %H", lgw->gwid.buf, 8);
    }

    if(lgw->beacon.flag){
        log_puts(LOG_NORMAL, "BEACON PERIOD %d", lgw->beacon.period);
        log_puts(LOG_NORMAL, "BEACON FREQ %d", lgw->beacon.freq);
    }

    if(lgw->mac_addr.flag){
        log_puts(LOG_NORMAL, "MACADDR %h", lgw->mac_addr.buf, 6);
    }
}
