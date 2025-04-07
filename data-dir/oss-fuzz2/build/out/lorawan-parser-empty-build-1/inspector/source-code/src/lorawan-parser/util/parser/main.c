#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <libgen.h>     // dirname, basename

#include "lw.h"
#include "parson.h"
#include "conf.h"
#include "str2hex.h"
#include "log.h"
#include "app.h"
#include "version.h"

/**
    JR: Join Request
    JA: Join Accept
    UU: Unconfirmed Data Up
    UD: Unconfirmed Data Down
    CU: Confirmed Data Up
    CD: Confirmed Data Down
    P:  Proprietary
*/
void usage(char *name)
{
    log_line();
    log_puts(LOG_NORMAL, "Usage: %s [OPTIONS]", name);
    log_puts(LOG_NORMAL, " -h, --help                     Help");
    log_puts(LOG_NORMAL, " -v, --version                  Version %d.%d.%d", VMAJOR, VMINOR, VPATCH);
    log_line();
    log_puts(LOG_NORMAL, " -c, --burst-parse  <file>      Parse lwp json format file");
    log_puts(LOG_NORMAL, " -m, --maccmd       <hex>       Parse MAC command");
    log_puts(LOG_NORMAL, " -p, --parse        [hex]       Parse packet");
    log_puts(LOG_NORMAL, " -g, --pack         [hex]       Generate packet");
    log_puts(LOG_NORMAL, " -f, --pktfwd       [file]      Packet forwarder mode");
    log_puts(LOG_NORMAL, "     --join                     Analyze JR and JA");
    log_line();
    log_puts(LOG_NORMAL, " -B, --band         <string>    PHY band EU868/US915/EU434/AU920/CN780/CN470");
    log_puts(LOG_NORMAL, " -N, --nwkskey      <hex>       NwkSKey");
    log_puts(LOG_NORMAL, " -A, --appskey      <hex>       AppSKey");
    log_puts(LOG_NORMAL, " -K, --appkey       <hex>       AppKey");
    log_line();
    log_puts(LOG_NORMAL, " -T, --type         <string>    Frame type (JR/JA/UU/UD/CU/CD/P)");
    log_puts(LOG_NORMAL, " -D, --devaddr      <hex>       DevAddr");
    log_puts(LOG_NORMAL, "     --ack                      FCtrl ACK");
    log_puts(LOG_NORMAL, "     --aareq                    FCtrl ADRACKReq");
    log_puts(LOG_NORMAL, "     --adr                      FCtrl ADR");
    log_puts(LOG_NORMAL, "     --classb                   FCtrl CLASSB");
    log_puts(LOG_NORMAL, "     --fpending                 FCtrl FPENDING");
    log_puts(LOG_NORMAL, " -O, --fopts        <hex>       FOpts, LoRaWAN Options");
    log_puts(LOG_NORMAL, " -C                 <hex>       Frame counter (hex)");
    log_puts(LOG_NORMAL, "     --counter      <int>       Frame counter (int)");
    log_puts(LOG_NORMAL, " -P                 <hex>       Port (hex)");
    log_puts(LOG_NORMAL, "     --port         <int>       Port (int)");
    log_line();
    log_puts(LOG_NORMAL, "     --appeui       <hex>       AppEui");
    log_puts(LOG_NORMAL, "     --deveui       <hex>       DevEui");
    log_puts(LOG_NORMAL, "     --anonce       <hex>       AppNonce (3 byets)");
    log_puts(LOG_NORMAL, "     --dnonce       <hex>       DevNonce (2 byets)");
    log_puts(LOG_NORMAL, "     --netid        <hex>       NetId (3 byets)");
    log_puts(LOG_NORMAL, "     --cflist       <hex>       CFList (16 bytes)");
    log_puts(LOG_NORMAL, "     --rx1droft     <int>       RX1DRoffset (0~7)");
    log_puts(LOG_NORMAL, "     --rx2dr        <int>       RX2DataRate (0~15)");
    log_puts(LOG_NORMAL, "     --rxdelay      <int>       RxDelay (0~15)");
    log_puts(LOG_NORMAL, "     --jr           <hex>       JoinRequest raw data");
    log_puts(LOG_NORMAL, "     --ja           <hex>       JoinAccept raw data");
    log_line();
    log_puts(LOG_NORMAL, "     --motes        <file>      Motes/Nodes JSON file");
    log_puts(LOG_NORMAL, "     --nodes        <file>      Same as --motes");
    log_line();
    log_puts(LOG_NORMAL, " -b, --board        <file>      Board specific TX power table and RSSI offset");
    log_puts(LOG_NORMAL, " -i, --iface        <string>    Network interface, default eth0");
    log_line();
    log_puts(LOG_INFO, "Default AppKey/NwkSKey/AppSKey 2B7E151628AED2A6ABF7158809CF4F3C");
}

int main(int argc, char **argv)
{
    int ret;
    char *pfile = NULL;
    message_t * ll_head;
    lw_frame_t frame;
    config_t config;
    app_opt_t opt;
    lw_key_grp_t kgrp;
    lw_node_t endnode;
    uint8_t msg[256];
    int len;

    memset(&config, 0, sizeof(config_t));

    log_init(LOG_NORMAL);

    if(argc == 1){
        usage(basename(argv[0]));
        return 0;
    }

    ret = app_getopt(&opt, argc, argv);
    if(ret < 0){
        log_puts(LOG_FATAL, "ERROR: (%s)", app_err(ret));
        usage(basename(argv[0]));
        return -1;
    }

    /* Uncomment to show options log */
    //app_log_opt(&opt);

    switch(opt.mode){
    case APP_MODE_HELP:
        usage(basename(argv[0]));
        return 0;
    case APP_MODE_VER:
        log_puts(LOG_NORMAL, "%d.%d.%d", VMAJOR, VMINOR, VPATCH);
        return 0;
    case APP_MODE_MACCMD:
        lw_init(opt.band);
        ret = lw_log_maccmd(opt.hdr.data, LW_MACCMD_FOPTS, opt.maccmd.buf, opt.maccmd.len);
        if(ret < 0){
            log_puts(LOG_ERROR, "MACCMD error(%d)", ret);
            return -1;
        }
        return 0;
    case APP_MODE_PARSE:
        lw_init(opt.band);
        kgrp.nwkskey = opt.nwkskey;
        kgrp.flag.bits.nwkskey = 1;
        kgrp.appskey = opt.appskey;
        kgrp.flag.bits.appskey = 1;
        kgrp.appkey = opt.appkey;
        kgrp.flag.bits.appkey = 1;
        lw_set_key(&kgrp);
        log_line();
        ret = lw_parse(&frame, opt.frame.buf, opt.frame.len);
        if(ret == LW_OK){
            lw_log(&frame, opt.frame.buf, opt.frame.len);
        }else{
            log_puts(LOG_ERROR, "DATA MESSAGE PARSE error(%d)", ret);
        }
        return 0;
    case APP_MODE_JOIN:
        lw_init(opt.band);
        kgrp.nwkskey = opt.nwkskey;
        kgrp.flag.bits.nwkskey = 1;
        kgrp.appskey = opt.appskey;
        kgrp.flag.bits.appskey = 1;
        kgrp.appkey = opt.appkey;
        kgrp.flag.bits.appkey = 1;
        lw_set_key(&kgrp);
        log_line();
        ret = lw_parse(&frame, opt.join.request.buf, opt.join.request.len);
        if(ret == LW_OK){
            lw_log(&frame, opt.join.request.buf, opt.join.request.len);
        }else{
            log_puts(LOG_ERROR, "JOIN REQUEST PARSE error(%d)", ret);
        }

        log_line();
        ret = lw_parse(&frame, opt.join.accept.buf, opt.join.accept.len);
        if(ret == LW_OK){
            lw_log(&frame, opt.join.accept.buf, opt.join.accept.len);
        }else{
            log_puts(LOG_ERROR, "JOIN ACCEPT PARSE error(%d)", ret);
        }
        return 0;
    case APP_MODE_BURST_PARSE:
        pfile = opt.cfile;
        break;
    case APP_MODE_PKT_FWD:
        return app_pkt_fwd(&opt);
    case APP_MODE_GENERATE:
        lw_init(opt.band);
        memset( (uint8_t *)&endnode, 0, sizeof(lw_node_t) );
        lw_cpy(endnode.appeui, opt.appeui, 8);
        lw_cpy(endnode.deveui, opt.deveui, 8);
        memcpy(endnode.appkey, opt.appkey, 16);
        memcpy(endnode.nwkskey, opt.nwkskey, 16);
        memcpy(endnode.appskey, opt.appskey, 16);
        endnode.devnonce = opt.dnonce;
        memset( (uint8_t *)&frame, 0, sizeof(lw_frame_t) );

        frame.node = &endnode;
        lw_cpy(frame.deveui, opt.deveui, 8);
        lw_cpy(frame.appeui, opt.appeui, 8);
        frame.mhdr.data = opt.hdr.data;
        switch(frame.mhdr.bits.mtype){
        case LW_MTYPE_JOIN_REQUEST:
            frame.pl.jr.devnonce.data = opt.dnonce.data;
            break;
        case LW_MTYPE_JOIN_ACCEPT:
            frame.pl.ja.appnonce.data = opt.anonce.data;
            frame.pl.ja.netid.data = opt.netid.data;
            frame.pl.ja.devaddr.data = opt.devaddr.data;
            frame.pl.ja.dlsettings.bits.rx1droft = opt.rx1droft;
            frame.pl.ja.dlsettings.bits.rx2dr = opt.rx2dr;
            frame.pl.ja.rxdelay.bits.del = opt.rxdelay;
            if(opt.cflist.len > 0){
                frame.pl.ja.cflist_len = opt.cflist.len;
                memcpy(frame.pl.ja.cflist, opt.cflist.buf, opt.cflist.len);
            }
            break;
        case LW_MTYPE_MSG_UP:
        case LW_MTYPE_MSG_DOWN:
        case LW_MTYPE_CMSG_UP:
        case LW_MTYPE_CMSG_DOWN:
            frame.pl.mac.devaddr.data = opt.devaddr.data;
            switch(frame.mhdr.bits.mtype){
            case LW_MTYPE_MSG_UP:
            case LW_MTYPE_CMSG_UP:
                frame.pl.mac.fctrl.ul.ack = opt.ack;
                frame.pl.mac.fctrl.ul.adr = opt.adr;
                frame.pl.mac.fctrl.ul.adrackreq = opt.adrackreq;
                frame.pl.mac.fctrl.ul.classb = opt.classb;
                break;
            case LW_MTYPE_CMSG_DOWN:
            case LW_MTYPE_MSG_DOWN:
                frame.pl.mac.fctrl.dl.ack = opt.ack;
                frame.pl.mac.fctrl.dl.adr = opt.adr;
                frame.pl.mac.fctrl.dl.fpending = opt.fpending;
                break;
            }
            frame.pl.mac.fcnt = opt.counter;
            if(opt.frame.len > 0){
                frame.pl.mac.fport = opt.port;
                frame.pl.mac.flen = opt.frame.len;
                memcpy(frame.pl.mac.fpl, opt.frame.buf, opt.frame.len);
            }
            if(opt.foptslen > 0){
                frame.pl.mac.fctrl.ul.foptslen = opt.foptslen;
                memcpy(frame.pl.mac.fopts, opt.fopts, opt.foptslen);
            }
            break;
        }
        if( lw_pack(&frame, msg, &len) > 0){
            log_line();
            lw_log(&frame, msg, len);
        }else{
            log_puts(LOG_FATAL, "LoRaWAN Pack error");
        }
        return 0;
    default:
        log_puts(LOG_FATAL, "UNKNOWN MODE");
        usage(basename(argv[0]));
        return -1;
    }

    if(opt.mode != APP_MODE_BURST_PARSE){
        log_puts(LOG_WARN, "Mode is not supported");
        return -1;
    }

    ret = config_parse(pfile, &config);
    if(ret < 0){
        log_puts(LOG_NORMAL, "Configuration parse error(%d)", ret);
        return -1;
    }

    lw_init(config.band);

    memset(&kgrp, 0, sizeof(lw_key_grp_t));
    if(config.flag&CFLAG_NWKSKEY){
        kgrp.nwkskey = config.nwkskey;
        kgrp.flag.bits.nwkskey = 1;
    }
    if(config.flag&CFLAG_APPSKEY){
        kgrp.appskey = config.appskey;
        kgrp.flag.bits.appskey = 1;
    }
    if(config.flag&CFLAG_APPKEY){
        kgrp.appkey = config.appkey;
        kgrp.flag.bits.appkey = 1;
    }
    lw_set_key(&kgrp);

    /** try to parse join request/accept message */
    if(config.flag&CFLAG_JOINR){
        log_line();
        if(LW_OK == lw_parse(&frame, config.joinr, config.joinr_size)){
            lw_log(&frame, config.joinr, config.joinr_size);
        }
    }

    if(config.flag&CFLAG_JOINA){
        log_line();
        /** If get join request and accept is parsed,
        then try to generate new key with JION transaction,
        the new generated key will be used to parse message */
        if(LW_OK == lw_parse(&frame, config.joina, config.joina_size)){
            lw_log(&frame, config.joina, config.joina_size);
        }else{
            log_puts(LOG_WARN, "JOIN REQUEST PARSE ERROR");
        }
    }

    /** parse all data message */
    ll_head = config.message;
    while(ll_head != NULL){
        log_line();
        ret = lw_parse(&frame, ll_head->buf, ll_head->len);
        if(ret == LW_OK){
            lw_log(&frame, ll_head->buf, ll_head->len);
        }else{
            log_puts(LOG_ERROR, "MSG: %H", ll_head->buf, ll_head->len);
            log_puts(LOG_ERROR, "DATA MESSAGE PARSE error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    /** parse command list */
    ll_head = config.maccmd;
    while(ll_head != NULL){
        log_line();
        /** buf[0] -> MHDR, buf[1] ~ buf[n] -> maccmd */
        ret = lw_log_maccmd(ll_head->buf[0], LW_MACCMD_FOPTS, ll_head->buf+1, ll_head->len-1);
        if(ret < 0){
            log_puts(LOG_ERROR, "MACCMD error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    lw_log_all_node();

    config_free(&config);

    return 0;
}
