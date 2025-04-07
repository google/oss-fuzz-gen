#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include "pktfwd.h"
#include "conf.h"
#include "log.h"
#include "lw.h"

#if defined _WIN32 || defined __CYGWIN__
#ifndef WIN32
#define WIN32
#endif // WIN32
#endif // __MINGW32__

#ifdef PKTFWD_DISABLE_ECHO
struct termios savedtty;
#endif

static void pktfwd_sig_handler(int sigio);

int pktfwd_init(config_lgw_t *lgw)
{
    struct termios newtty;
    struct sigaction sig;
    int i, ret;

    if (lgw_board_setconf(lgw->board.conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: Failed to configure board");
    }

    if (lgw_lbt_setconf(lgw->lbt.conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: Failed to configure lbt");
    }

    if (lgw_txgain_setconf(&lgw->txlut.conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: Failed to configure concentrator TX Gain LUT");
    }

    for (i=0; i<LGW_RF_CHAIN_NB; i++) {
        if (lgw_rxrf_setconf(i, lgw->radio[i].conf) != LGW_HAL_SUCCESS) {
            log_puts(LOG_NORMAL, "WARNING: invalid configuration for radio %i", i);
        }
    }

    for (i = 0; i < LGW_MULTI_NB; ++i) {
        if (lgw_rxif_setconf(i, lgw->chan[i].conf) != LGW_HAL_SUCCESS) {
             log_puts(LOG_NORMAL, "WARNING: invalid configuration for Lora multi-SF channel %i", i);
        }
    }

    if (lgw_rxif_setconf(8, lgw->chan[8].conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: invalid configuration for Lora multi-SF channel %i", i);
    }

    if (lgw_rxif_setconf(9, lgw->chan[9].conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: invalid configuration for Lora multi-SF channel %i", i);
    }

    sigemptyset (&sig.sa_mask);
    sig.sa_handler = pktfwd_sig_handler;
    sig.sa_flags = 0;
    sigaction(SIGQUIT, &sig, NULL);
    sigaction(SIGINT, &sig, NULL);
    sigaction(SIGTERM, &sig, NULL);

#ifdef PKTFWD_DISABLE_ECHO
    if(tcgetattr(STDIN_FILENO, &savedtty) != 0){
        log_puts(LOG_FATAL, "Fatal error tcgetattr");
        exit(EXIT_FAILURE);
    }

    newtty = savedtty;
    newtty.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &newtty);
#endif

    ret = lgw_start();
    if (ret == LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "Concentrator started");
    } else {
        log_puts(LOG_NORMAL, "Concentrator failed to start");
        exit(EXIT_FAILURE);
    }

    return 0;
}

static void pktfwd_sig_handler(int sigio)
{
    int ret;

    ret = lgw_stop();
    if (ret == LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "Concentrator stopped");
    } else {
        log_puts(LOG_NORMAL, "Concentrator fail to stop");
    }

#ifdef PKTFWD_DISABLE_ECHO
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &savedtty);
#endif

    exit(EXIT_SUCCESS);
}

void pktfwd_test(void)
{
    struct lgw_pkt_rx_s rxpkt[8]; /* array containing inbound packets + metadata */
    struct lgw_pkt_rx_s *p; /* pointer on a RX packet */
    int i, nb_pkt;

    nb_pkt = lgw_receive(8, rxpkt);
    if(nb_pkt == LGW_HAL_ERROR){
        exit(EXIT_FAILURE);
    }
    if(nb_pkt > 0){
        for (i=0; i < nb_pkt; ++i) {
            p = &rxpkt[i];
            lw_log_rxpkt(p);
        }
    }

}

void pktfwd_evt(void)
{
    while(1){
        pktfwd_test();
    }
}

