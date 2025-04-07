#ifndef __PACKET_FORWARDER_H__
#define __PACKET_FORWARDER_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "conf.h"

#include "loragw_reg.h"
#include "loragw_hal.h"
#include "loragw_aux.h"
#if ! defined _WIN32 && ! defined __CYGWIN__
#include "loragw_gps.h"
#include "loragw_lbt.h"
#endif

//#define PKTFWD_DISABLE_ECHO

int pktfwd_init(config_lgw_t *lgw);
void pktfwd_evt(void);


#endif
